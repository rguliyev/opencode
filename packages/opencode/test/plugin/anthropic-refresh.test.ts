import { describe, expect, test } from "bun:test"
import path from "node:path"
import { tmpdir } from "../fixture/fixture"
import {
  freshAnthropicAuth,
  refreshExpiry,
  refreshOptions,
  type RefreshOptions,
} from "../../../../contrib/subscription-fallback/anthropic-refresh"
import { createOpencodeClient } from "@opencode-ai/sdk"
import type { Auth } from "@opencode-ai/sdk"

function scenario(lockDir: string) {
  let auth: Auth & { refreshExpiresAt?: number } = {
    type: "oauth",
    access: "old-access",
    refresh: "old-refresh",
    expires: 1,
  }
  const messages: string[] = []
  let calls = 0
  let saves = 0
  const options: RefreshOptions = {
    lockDir,
    getAuth: async () => ({ ...auth }),
    save: async (value, expected) => {
      saves++
      if (auth.type !== "oauth" || auth.refresh !== expected) return false
      auth = value
      return true
    },
    notify: async (notice) => {
      messages.push(notice.message)
    },
    log: async (message) => {
      messages.push(message)
    },
    transport: Object.assign(
      async () => {
        calls++
        await Bun.sleep(20)
        return Response.json({ access_token: "new-access", refresh_token: "new-refresh", expires_in: 3600 })
      },
      { preconnect: fetch.preconnect },
    ) as typeof fetch,
  }
  return {
    options,
    messages,
    get auth() {
      return auth
    },
    set auth(value) {
      auth = value
    },
    get calls() {
      return calls
    },
    get saves() {
      return saves
    },
  }
}

test("independent loader instances share refresh lock, reread under it, and rotate once", async () => {
  await using tmp = await tmpdir()
  const s = scenario(tmp.path)
  const result = await Promise.all(Array.from({ length: 6 }, () => freshAnthropicAuth({ ...s.options })))
  expect(s.calls).toBe(1)
  expect(s.saves).toBe(1)
  expect(result.every((x) => x.type === "oauth" && x.access === "new-access")).toBe(true)
  expect(s.messages.join(" ")).not.toMatch(/old-refresh|new-refresh|old-access|new-access/)
})

test("real SDK error results are rejected and no falsely successful refresh escapes", async () => {
  await using tmp = await tmpdir()
  const s = scenario(tmp.path)
  const client = createOpencodeClient({
    baseUrl: "http://unused",
    fetch: async () => Response.json({ error: "failed" }, { status: 500 }),
  })
  s.options.save = refreshOptions({ client } as never, s.options.getAuth).save
  await expect(freshAnthropicAuth(s.options)).rejects.toThrow("Failed to persist")
  expect(s.calls).toBe(1)
  expect(s.auth.type === "oauth" && s.auth.refresh).toBe("old-refresh")
  await expect(freshAnthropicAuth(s.options)).rejects.toThrow("reauthentication")
  expect(s.calls).toBe(1)
})

test("retries persistence of the same rotated pair, not the exchange", async () => {
  await using tmp = await tmpdir()
  const s = scenario(tmp.path)
  const save = s.options.save
  let attempts = 0
  s.options.save = async (...args) => {
    if (++attempts === 1) throw new Error("disk temporarily unavailable")
    return save(...args)
  }
  await freshAnthropicAuth(s.options)
  expect(s.calls).toBe(1)
  expect(attempts).toBe(2)
})

test("invalid_grant recovers only from a newer usable credential, not by retrying the same token", async () => {
  await using tmp = await tmpdir()
  const s = scenario(tmp.path)
  s.options.transport = Object.assign(
    async () => {
      s.auth = { type: "oauth", access: "external-access", refresh: "external-refresh", expires: Date.now() + 3600000 }
      return Response.json({ error: "invalid_grant" }, { status: 400 })
    },
    { preconnect: fetch.preconnect },
  ) as typeof fetch
  const result = await freshAnthropicAuth(s.options)
  expect(result.type === "oauth" && result.access).toBe("external-access")
  expect(s.saves).toBe(0)
})

test("rejected refresh warns once, suppresses retries until reauth, and never logs provider secrets", async () => {
  await using tmp = await tmpdir()
  const s = scenario(tmp.path)
  let calls = 0
  s.options.transport = Object.assign(
    async () => {
      calls++
      return Response.json(
        { error: "invalid_grant", error_description: "secret-refresh-from-provider" },
        { status: 400 },
      )
    },
    { preconnect: fetch.preconnect },
  ) as typeof fetch
  await expect(freshAnthropicAuth(s.options)).rejects.toThrow("invalid_grant")
  await expect(freshAnthropicAuth(s.options)).rejects.toThrow("reauthentication")
  expect(calls).toBe(1)
  expect(s.messages.join(" ")).not.toContain("secret-refresh")
  s.auth = { type: "oauth", access: "signed-in", refresh: "different", expires: Date.now() + 3600000 }
  expect((await freshAnthropicAuth(s.options)).type).toBe("oauth")
})

test("concurrent reauthentication is not overwritten after exchange", async () => {
  await using tmp = await tmpdir()
  const s = scenario(tmp.path)
  const transport = s.options.transport!
  s.options.transport = Object.assign(
    async (...args: Parameters<typeof fetch>) => {
      const response = await transport(...args)
      s.auth = { type: "oauth", access: "login-access", refresh: "login-refresh", expires: Date.now() + 3600000 }
      return response
    },
    { preconnect: fetch.preconnect },
  ) as typeof fetch
  const result = await freshAnthropicAuth(s.options)
  expect(result.type === "oauth" && result.refresh).toBe("login-refresh")
})

test("refresh deadline is preserved without new server metadata; warnings are bounded", async () => {
  await using tmp = await tmpdir()
  const s = scenario(tmp.path)
  const deadline = Date.now() + 86400000
  s.auth = { ...s.auth, refreshExpiresAt: deadline }
  await freshAnthropicAuth(s.options)
  await freshAnthropicAuth(s.options)
  expect(s.auth.refreshExpiresAt).toBe(deadline)
  expect(s.messages.filter((x) => x.includes("renewal expires"))).toHaveLength(2) // toast + log, once
  expect(refreshExpiry(undefined)).toBeUndefined()
  expect(refreshExpiry(undefined, deadline)).toBe(deadline)
  expect(refreshExpiry(-1, deadline)).toBe(deadline)
  expect(refreshExpiry(60)).toBeGreaterThan(Date.now() + 59000)
})

test("API key and unexpired OAuth pass through without a token exchange", async () => {
  await using tmp = await tmpdir()
  const s = scenario(tmp.path)
  s.auth = { type: "api", key: "fake" }
  expect(await freshAnthropicAuth(s.options)).toEqual(s.auth)
  s.auth = { type: "oauth", access: "valid", refresh: "valid-refresh", expires: Date.now() + 3600000 }
  await freshAnthropicAuth(s.options)
  expect(s.calls).toBe(0)
})

test("two independent processes serialize renewal using the shared file lock", async () => {
  await using tmp = await tmpdir()
  const file = path.join(tmp.path, "fake-auth.json")
  await Bun.write(file, JSON.stringify({ type: "oauth", access: "old", refresh: "old", expires: 1 }))
  let exchanges = 0
  using server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch() {
      exchanges++
      await Bun.sleep(150)
      return Response.json({ access_token: "new", refresh_token: "new", expires_in: 3600 })
    },
  })
  const children = Array.from({ length: 2 }, () =>
    Bun.spawn(
      [process.execPath, path.join(import.meta.dir, "../fixture/anthropic-refresh-worker.ts"), file, server.url.href],
      { env: { ...process.env }, stdout: "pipe", stderr: "pipe" },
    ),
  )
  for (const child of children) {
    expect(await child.exited).toBe(0)
    expect(await new Response(child.stdout).text()).toBe("ok\n")
  }
  expect(exchanges).toBe(1)
}, 15000)

const bundles = process.env.FALLBACK_PLUGIN_BUNDLES
describe.skipIf(!bundles)("actual bundled Anthropic plugin", () => {
  test("preserves login refresh expiry and renews across two loaders without upstream races", async () => {
    const module = await import(path.join(bundles!, "anthropic.js"))
    let auth = {
      type: "oauth" as const,
      access: "old-access",
      refresh: "old-refresh",
      expires: 1,
      refreshExpiresAt: Date.now() + 86400000,
    }
    let rotations = 0
    let requests = 0
    const original = fetch
    globalThis.fetch = Object.assign(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = input instanceof Request ? input.url : String(input)
        if (url === "https://platform.claude.com/v1/oauth/token") {
          const body = JSON.parse(String(init?.body))
          if (body.grant_type === "refresh_token") rotations++
          await Bun.sleep(20)
          return Response.json({
            access_token: "new-access",
            refresh_token: "new-refresh",
            expires_in: 3600,
            refresh_token_expires_in: 7200,
          })
        }
        expect(url).toStartWith("https://api.anthropic.com/")
        expect(new Headers(init?.headers).get("authorization")).toBe("Bearer new-access")
        requests++
        return new Response("included")
      },
      { preconnect: original.preconnect },
    ) as typeof fetch
    try {
      const client = createOpencodeClient({
        baseUrl: "http://fake-api",
        fetch: async (input) => {
          const req = input as Request
          if (new URL(req.url).pathname === "/auth/anthropic") {
            const { expectedRefresh, ...value } = await req.json()
            if (expectedRefresh !== auth.refresh) return Response.json(false)
            auth = value
          }
          return Response.json(true)
        },
      })
      const hooks = await module.default(
        { client, capabilities: { authConditionalWrite: true } },
        { credentials: "/unused-fallback" },
      )
      const method = hooks.auth.methods.find((x: { label: string }) => x.label === "Claude Pro/Max")
      const flow = await method.authorize()
      const state = new URL(flow.url).searchParams.get("state")
      const login = await flow.callback(`fake-code#${state}`)
      expect(login.type).toBe("success")
      expect(login.refreshExpiresAt).toBeGreaterThan(Date.now() + 7190000)
      const load = () => hooks.auth.loader(async () => ({ ...auth }), { models: {} })
      const a = await load()
      const b = await load()
      expect(rotations).toBe(0) // No refresh/model request while loading provider.
      const call = (options: { fetch: typeof fetch }) =>
        options.fetch("https://api.anthropic.com/v1/messages", {
          method: "POST",
          body: JSON.stringify({ model: "fake", messages: [] }),
        })
      const responses = await Promise.all([call(a), call(b)])
      expect(await Promise.all(responses.map((x) => x.text()))).toEqual(["included", "included"])
      expect(rotations).toBe(1)
      expect(requests).toBe(2)
      expect(auth.refreshExpiresAt).toBeGreaterThan(Date.now() + 7190000)
    } finally {
      globalThis.fetch = original
    }
  })
})

test("old running servers cannot rotate tokens before the binary is restarted", async () => {
  await using tmp = await tmpdir()
  const s = scenario(tmp.path)
  s.options.ensureReady = refreshOptions({} as never, async () => s.auth).ensureReady
  await expect(freshAnthropicAuth(s.options)).rejects.toThrow("Restart OpenCode")
  expect(s.calls).toBe(0)
})

test("concurrent logout stops the request and cannot resurrect the credential", async () => {
  await using tmp = await tmpdir()
  const s = scenario(tmp.path)
  const transport = s.options.transport!
  s.options.transport = Object.assign(
    async (...args: Parameters<typeof fetch>) => {
      const response = await transport(...args)
      s.options.getAuth = async () => undefined
      s.options.save = async () => false
      return response
    },
    { preconnect: fetch.preconnect },
  ) as typeof fetch
  await expect(freshAnthropicAuth(s.options)).rejects.toThrow("credentials changed")
  expect(s.saves).toBe(0)
})

for (const failure of ["lost", "malformed", "save-fail", "invalid-grant"]) {
  test(`two processes do not reuse a token after ${failure}`, async () => {
    await using tmp = await tmpdir()
    const file = path.join(tmp.path, "fake-auth.json")
    await Bun.write(file, JSON.stringify({ type: "oauth", access: "old-access", refresh: "old-refresh", expires: 1 }))
    let exchanges = 0
    using server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      async fetch() {
        exchanges++
        await Bun.sleep(100)
        if (failure === "malformed") return new Response("invalid JSON")
        if (failure === "invalid-grant") return Response.json({ error: "invalid_grant" }, { status: 400 })
        return Response.json({ access_token: "new-access", refresh_token: "new-refresh", expires_in: 3600 })
      },
    })
    const children = Array.from({ length: 2 }, () =>
      Bun.spawn(
        [
          process.execPath,
          path.join(import.meta.dir, "../fixture/anthropic-refresh-worker.ts"),
          file,
          server.url.href,
          failure,
        ],
        { env: { ...process.env }, stdout: "pipe", stderr: "pipe" },
      ),
    )
    for (const child of children) {
      expect(await child.exited).toBe(0)
      expect(await new Response(child.stdout).text()).toBe("blocked\n")
    }
    expect(exchanges).toBe(1)
    const journal = await Bun.file(path.join(tmp.path, "locks/.anthropic-oauth-renewal.json")).text()
    expect(journal).not.toMatch(/old-refresh|new-refresh|old-access|new-access/)
    expect(JSON.parse(journal).fingerprint).toMatch(/^[a-f0-9]{64}$/)
  }, 15000)
}

test("lost response is quarantined for the next caller in the same process", async () => {
  await using tmp = await tmpdir()
  const s = scenario(tmp.path)
  let calls = 0
  s.options.transport = Object.assign(
    async () => {
      calls++
      throw new Error("lost response")
    },
    { preconnect: fetch.preconnect },
  ) as typeof fetch
  await expect(freshAnthropicAuth(s.options)).rejects.toThrow("network/timeout")
  await expect(freshAnthropicAuth(s.options)).rejects.toThrow("reauthentication")
  expect(calls).toBe(1)
})
