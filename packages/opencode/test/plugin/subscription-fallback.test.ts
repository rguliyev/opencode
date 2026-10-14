import { describe, expect, test } from "bun:test"
import { createSubscriptionFallback } from "../../../../contrib/subscription-fallback/fallback"
import type { Auth } from "../../src/auth"

const subscription: Auth.Info = { type: "oauth", access: "subscription", refresh: "refresh", expires: 9999999999999 }
const pat: Auth.Info = { type: "oauth", access: "at-paid", refresh: "", expires: 9999999999999 }
const api: Auth.Info = { type: "api", key: "paid-api-key" }
const body = JSON.stringify({ model: "test-model", stream: true, input: [] })
const request = {
  method: "POST",
  body,
  headers: { authorization: "Bearer subscription", "chatgpt-account-id": "primary-account", "session-id": "session" },
}
function quota(provider: "openai" | "anthropic", reset = 2000) {
  return Response.json(
    { error: { type: provider === "openai" ? "usage_limit_reached" : "rate_limit_error", resets_at: reset } },
    {
      status: 429,
      headers:
        provider === "anthropic"
          ? {
              "anthropic-ratelimit-unified-5h-status": "rejected",
              "anthropic-ratelimit-unified-5h-reset": String(reset),
            }
          : {},
    },
  )
}
function setup(
  provider: "openai" | "anthropic",
  primary: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>,
) {
  const state = {
    now: 1000000,
    auth: subscription,
    fallback: (provider === "openai" ? pat : api) as Auth.Info | undefined,
  }
  const notices: Array<{ message: string; variant: string }> = []
  const calls: Array<{ url: string; init?: RequestInit }> = []
  const run = createSubscriptionFallback({
    provider,
    primary,
    now: () => state.now,
    getPrimary: async () => state.auth,
    getFallback: async () => state.fallback,
    notify: async (notice) => {
      notices.push(notice)
    },
    transport: async (input, init) => {
      calls.push({ url: input.toString(), init })
      return new Response("paid")
    },
  })
  const url = provider === "openai" ? "https://api.openai.com/v1/responses" : "https://api.anthropic.com/v1/messages"
  return { state, notices, calls, run: (init = request) => run(url, init), fetch: run }
}

describe.each(["openai", "anthropic"] as const)("%s subscription fallback", (provider) => {
  test("subscription success never spends paid credentials", async () => {
    const t = setup(provider, async () => new Response("included"))
    expect(await (await t.run()).text()).toBe("included")
    expect(t.calls).toHaveLength(0)
    expect(t.notices).toHaveLength(0)
  })
  test("quota switches once, warns, retries primary after 60s and returns automatically", async () => {
    let requests = 0
    const t = setup(provider, async () => (++requests === 1 ? quota(provider) : new Response("restored")))
    expect(await (await t.run()).text()).toBe("paid")
    expect(t.notices[0].message).toContain("PAID fallback")
    expect(t.notices[0].message).toContain("reset")
    expect(await (await t.run()).text()).toBe("paid")
    expect(requests).toBe(1)
    expect(t.notices).toHaveLength(1)
    t.state.now += 60001
    expect(await (await t.run()).text()).toBe("restored")
    expect(t.notices.at(-1)?.variant).toBe("success")
    expect(t.calls).toHaveLength(2)
  })
  test("does not switch for auth, permission, server, or generic rate errors", async () => {
    for (const status of [400, 401, 403, 429, 500, 529]) {
      const t = setup(provider, async () => Response.json({ error: { type: "rate_limit_error" } }, { status }))
      expect((await t.run()).status).toBe(status)
      expect(t.calls).toHaveLength(0)
    }
  })
  test("missing fallback warns and preserves original quota response", async () => {
    const t = setup(provider, async () => quota(provider))
    t.state.fallback = undefined
    const res = await t.run()
    expect(res.status).toBe(429)
    expect((await res.json()).error).toBeDefined()
    expect(t.notices[0].message).toContain("NOT started")
    expect(t.calls).toHaveLength(0)
  })
  test("removing fallback takes effect immediately during cooldown", async () => {
    const t = setup(provider, async () => quota(provider))
    await t.run()
    t.state.fallback = undefined
    expect((await t.run()).status).toBe(429)
    expect(t.calls).toHaveLength(1)
  })
  test("never retries streaming errors or network failures", async () => {
    const t = setup(
      provider,
      async () =>
        new Response('event: error\ndata: {"error":{"type":"usage_limit_reached"}}\n\n', {
          headers: { "content-type": "text/event-stream" },
        }),
    )
    expect((await t.run()).status).toBe(200)
    expect(t.calls).toHaveLength(0)
    const failed = setup(provider, async () => {
      throw new Error("network")
    })
    await expect(failed.run()).rejects.toThrow("network")
    expect(failed.calls).toHaveLength(0)
  })
  test("abort prevents paid replay", async () => {
    const ctl = new AbortController()
    const t = setup(provider, async () => {
      ctl.abort()
      return quota(provider)
    })
    await expect(t.run({ ...request, signal: ctl.signal } as typeof request)).rejects.toThrow()
    expect(t.calls).toHaveLength(0)
  })
  test("request payload unchanged and subscription identity never leaks to fallback", async () => {
    const t = setup(provider, async (_input, init) => {
      new Headers(init?.headers)
      return quota(provider)
    })
    await t.run()
    const headers = new Headers(t.calls[0].init?.headers)
    expect(headers.get("chatgpt-account-id")).toBeNull()
    expect(t.calls[0].init?.body).toBe(body)
    expect(headers.get("authorization")).toBe(provider === "openai" ? "Bearer at-paid" : null)
    expect(headers.get("x-api-key")).toBe(provider === "anthropic" ? "paid-api-key" : null)
    expect(t.calls[0].init?.redirect).toBe("error")
    expect(request.headers.authorization).toBe("Bearer subscription")
  })
  test("does not send fallback to custom endpoints", async () => {
    const t = setup(provider, async () => quota(provider))
    expect((await t.fetch("https://custom.example/v1/responses", request)).status).toBe(429)
    expect(t.calls).toHaveLength(0)
  })
  test("API-only primary never enters subscription fallback", async () => {
    const t = setup(provider, async () => quota(provider))
    t.state.auth = api
    expect((await t.run()).status).toBe(429)
    expect(t.calls).toHaveLength(0)
  })
  test("quota is model-scoped and warning is session-scoped", async () => {
    let requests = 0
    const t = setup(provider, async () => {
      requests++
      return quota(provider)
    })
    await t.run()
    await t.run({ ...request, headers: { ...request.headers, "session-id": "other" } })
    expect(requests).toBe(1)
    expect(t.notices).toHaveLength(2)
    await t.run({ ...request, body: JSON.stringify({ model: "other-model" }) })
    expect(requests).toBe(2)
  })
  test("credential change invalidates previous cooldown", async () => {
    let requests = 0
    const t = setup(provider, async () => {
      requests++
      return quota(provider)
    })
    await t.run()
    t.state.auth = { ...subscription, refresh: "new-login" }
    await t.run()
    expect(requests).toBe(2)
  })
  test("warns at 90 percent before fallback", async () => {
    const headers: Record<string, string> =
      provider === "openai"
        ? { "x-codex-primary-used-percent": "90" }
        : { "anthropic-ratelimit-unified-5h-utilization": "0.9" }
    const t = setup(provider, async () => new Response("ok", { headers }))
    await t.run()
    expect(t.notices[0].message).toContain("90%")
    expect(t.calls).toHaveLength(0)
  })
})

describe.each(["openai", "anthropic"] as const)("%s loopback transport", (provider) => {
  test("real HTTP quota response retries once with paid auth and shows warning", async () => {
    const received: Array<{ path: string; auth: string | null; key: string | null; body: string }> = []
    const notices: string[] = []
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      async fetch(req) {
        const path = new URL(req.url).pathname
        received.push({
          path,
          auth: req.headers.get("authorization"),
          key: req.headers.get("x-api-key"),
          body: await req.text(),
        })
        return path === "/primary"
          ? quota(provider)
          : new Response("data: paid-ok\n\n", { headers: { "content-type": "text/event-stream" } })
      },
    })
    try {
      const run = createSubscriptionFallback({
        provider,
        getPrimary: async () => subscription,
        getFallback: async () => (provider === "openai" ? pat : api),
        primary: async (_url, init) => fetch(new URL("primary", server.url), init),
        transport: async (url, init) => {
          expect(new URL(url.toString()).hostname).toBe(provider === "openai" ? "chatgpt.com" : "api.anthropic.com")
          return fetch(new URL("paid", server.url), init)
        },
        notify: async (notice) => {
          notices.push(notice.message)
        },
      })
      const endpoint =
        provider === "openai" ? "https://api.openai.com/v1/responses" : "https://api.anthropic.com/v1/messages"
      const response = await run(endpoint, request)
      expect(await response.text()).toBe("data: paid-ok\n\n")
      expect(received).toHaveLength(2)
      expect(received[0].auth).toBe("Bearer subscription")
      expect(received[1].auth).toBe(provider === "openai" ? "Bearer at-paid" : null)
      expect(received[1].key).toBe(provider === "anthropic" ? "paid-api-key" : null)
      expect(received[1].body).toBe(received[0].body)
      expect(notices[0]).toContain("PAID")
    } finally {
      await server.stop(true)
    }
  })
  test("paid quota failure warns and is returned without another retry", async () => {
    const notices: string[] = []
    let attempts = 0
    const run = createSubscriptionFallback({
      provider,
      getPrimary: async () => subscription,
      getFallback: async () => (provider === "openai" ? pat : api),
      primary: async () => quota(provider),
      transport: async () => {
        attempts++
        return quota(provider)
      },
      notify: async (notice) => {
        notices.push(notice.message)
      },
    })
    const endpoint =
      provider === "openai" ? "https://api.openai.com/v1/responses" : "https://api.anthropic.com/v1/messages"
    expect((await run(endpoint, request)).status).toBe(429)
    expect(attempts).toBe(1)
    expect(notices.at(-1)).toContain("paid fallback failed")
  })
})

test("OpenAI WebSocket quota is handled before any streamed output", async () => {
  const { CodexAuthPlugin } = await import("../../src/plugin/openai/codex")
  const authorizations: string[] = []
  using server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(req, server) {
      authorizations.push(req.headers.get("authorization") ?? "")
      if (server.upgrade(req)) return
      return new Response("upgrade required", { status: 400 })
    },
    websocket: {
      message(socket) {
        socket.send(
          JSON.stringify({ type: "error", status_code: 429, error: { type: "usage_limit_reached", resets_at: 2000 } }),
        )
      },
    },
  })
  const hooks = await CodexAuthPlugin({} as never, {
    experimentalWebSockets: true,
    codexApiEndpoint: new URL("/backend-api/codex/responses", server.url).href,
  })
  const loaded = await hooks.auth!.loader!(async () => subscription, {} as never)
  let paid = 0
  const run = createSubscriptionFallback({
    provider: "openai",
    primary: loaded.fetch!,
    getPrimary: async () => subscription,
    getFallback: async () => pat,
    notify: async () => {},
    transport: async () => {
      paid++
      return new Response("paid")
    },
  })
  try {
    expect(await (await run("https://api.openai.com/v1/responses", request)).text()).toBe("paid")
    expect(paid).toBe(1)
    expect(authorizations).toEqual(["Bearer subscription"])
  } finally {
    await hooks.event?.({ event: { type: "server.instance.disposed", properties: { directory: "test" } } } as never)
  }
})

test("Anthropic unified rejection without per-window status is recognized", async () => {
  const t = setup("anthropic", async () =>
    Response.json(
      { error: { type: "rate_limit_error" } },
      {
        status: 429,
        headers: {
          "anthropic-ratelimit-unified-status": "rejected",
          "anthropic-ratelimit-unified-reset": "not-a-date",
        },
      },
    ),
  )
  expect(await (await t.run()).text()).toBe("paid")
  expect(t.notices[0].message).not.toContain("Invalid Date")
})

test("invalid reset timestamp cannot break fallback", async () => {
  const t = setup("openai", async () => quota("openai", 1e100))
  expect(await (await t.run()).text()).toBe("paid")
})
