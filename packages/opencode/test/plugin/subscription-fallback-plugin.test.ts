import { describe, expect, test } from "bun:test"
import type { Plugin } from "@opencode-ai/plugin"
import { chmod } from "node:fs/promises"
import path from "node:path"
import { pathToFileURL } from "node:url"
import { tmpdir } from "../fixture/fixture"
import { credentialPath, readFallback, wrapAuth } from "../../../../contrib/subscription-fallback/plugin"

test("private fallback file rejects relative, public, malformed, expired and wrong credentials", async () => {
  await using tmp = await tmpdir()
  const file = path.join(tmp.path, "fallback.json")
  expect(() => credentialPath({ credentials: "relative" })).toThrow()
  expect(await readFallback(file, "openai")).toBeUndefined()
  await Bun.write(file, JSON.stringify({ "openai-fallback": { type: "oauth", access: "at-test", refresh: "" } }))
  await chmod(file, 0o644)
  expect(await readFallback(file, "openai")).toBeUndefined()
  await chmod(file, 0o600)
  expect((await readFallback(file, "openai"))?.type).toBe("oauth")
  expect(await readFallback(file, "anthropic")).toBeUndefined()
  for (const value of [
    { type: "oauth", access: "at-test", refresh: "", expires: 1 },
    { type: "oauth", access: "at-test", refresh: "unexpected" },
    { type: "oauth", access: "not-a-pat", refresh: "" },
    { type: "api", key: "sk-platform" },
  ]) {
    await Bun.write(file, JSON.stringify({ "openai-fallback": value }))
    expect(await readFallback(file, "openai")).toBeUndefined()
  }
  await Bun.write(file, "invalid json")
  expect(await readFallback(file, "openai")).toBeUndefined()
})

test("wrapper preserves auth methods, unrelated hooks and API-key passthrough", async () => {
  const methods = [{ type: "api" as const, label: "API key" }]
  const event = async () => {}
  const wrapped = wrapAuth(
    { auth: { provider: "anthropic", methods, loader: async () => ({}) }, event },
    {} as never,
    "anthropic",
    "/unused",
  )
  expect(wrapped.auth.methods).toBe(methods)
  expect(wrapped.event).toBe(event)
  expect(await wrapped.auth.loader(async () => ({ type: "api", key: "test" }), {} as never)).toEqual({})
})

const bundles = process.env.FALLBACK_PLUGIN_BUNDLES
describe.skipIf(!bundles)("actual built plugin bundles, loopback transport", () => {
  for (const provider of ["openai", "anthropic"] as const) {
    test(`${provider}: subscription first, quota-only paid switch, warning, private credentials unchanged`, async () => {
      await using tmp = await tmpdir()
      const file = path.join(tmp.path, "fallback.json")
      const stored = JSON.stringify({
        "openai-fallback": { type: "oauth", access: "at-test-paid", refresh: "", expires: Date.now() + 60000 },
        "anthropic-fallback": { type: "api", key: "sk-test-paid" },
      })
      await Bun.write(file, stored)
      await chmod(file, 0o600)
      const notices: string[] = []
      const logs: string[] = []
      const requests: Array<{ headers: Headers; body: string }> = []
      let limit = false
      let native = false
      using server = Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        async fetch(req) {
          requests.push({ headers: req.headers, body: await req.text() })
          if (native)
            return new Response("native-extra-usage", {
              headers: {
                "anthropic-ratelimit-unified-status": "rejected",
                "anthropic-ratelimit-unified-overage-status": "allowed",
              },
            })
          const paid =
            req.headers.get("authorization") === "Bearer at-test-paid" ||
            req.headers.get("x-api-key") === "sk-test-paid"
          if (paid) {
            expect(notices.at(-1)).toContain("PAID fallback")
            return new Response("paid")
          }
          if (!limit) return new Response("included")
          return Response.json(
            { error: { type: provider === "openai" ? "usage_limit_reached" : "rate_limit_error" } },
            {
              status: 429,
              headers: { "anthropic-ratelimit-unified-5h-status": "rejected" },
            },
          )
        },
      })
      // The existing auth plugins do not inject transport. Patch fetch only in
      // this isolated test, redirect every provider request to real loopback HTTP.
      const original = globalThis.fetch
      const urls: URL[] = []
      globalThis.fetch = Object.assign(
        async (input: RequestInfo | URL, init?: RequestInit) => {
          urls.push(new URL(input instanceof Request ? input.url : input.toString()))
          return original(server.url, init)
        },
        { preconnect: original.preconnect },
      ) as typeof fetch
      let hooks: Awaited<ReturnType<Plugin>> | undefined
      try {
        const module = await import(pathToFileURL(path.join(bundles!, `${provider}.js`)).href)
        expect(Object.keys(module)).toEqual(["default"])
        const plugin = module.default as Plugin
        hooks = await plugin(
          {
            client: {
              tui: {
                showToast: async ({ body }: { body: { message: string } }) => {
                  notices.push(body.message)
                },
              },
              app: {
                log: async ({ body }: { body: { message: string } }) => {
                  logs.push(body.message)
                },
              },
              auth: {
                set: async () => {
                  throw new Error("Test must not change auth")
                },
              },
            },
          } as never,
          { credentials: file, experimentalWebSockets: false },
        )
        const auth = {
          type: "oauth" as const,
          access: "subscription-test",
          refresh: "refresh-test",
          expires: Date.now() + 60000,
          accountId: "subscription-workspace",
        }
        const loaded = await hooks.auth!.loader!(async () => ({ ...auth }), { models: {} } as never)
        const endpoint =
          provider === "openai" ? "https://api.openai.com/v1/responses" : "https://api.anthropic.com/v1/messages"
        const body = JSON.stringify({
          model: "test-model",
          stream: true,
          input: [],
          messages: [],
          system: "original",
          tools: [],
        })
        const request = {
          method: "POST",
          body,
          headers: {
            "content-type": "application/json",
            "session-id": "test-session",
            "chatgpt-account-id": "subscription-workspace",
            "anthropic-version": "2023-06-01",
          },
        }
        expect(await (await loaded.fetch(endpoint, request)).text()).toBe("included")
        expect(requests).toHaveLength(1)
        expect(notices).toHaveLength(0)
        limit = true
        expect(await (await loaded.fetch(endpoint, request)).text()).toBe("paid")
        expect(requests).toHaveLength(3)
        expect(requests[1].headers.get("authorization")).toBe("Bearer subscription-test")
        expect(requests[2].headers.has("chatgpt-account-id")).toBe(false)
        expect(requests[2].body).toBe(body)
        expect(requests[2].headers.get("authorization")).toBe(provider === "openai" ? "Bearer at-test-paid" : null)
        expect(requests[2].headers.get("x-api-key")).toBe(provider === "anthropic" ? "sk-test-paid" : null)
        expect(urls[2].href).toBe(provider === "openai" ? "https://chatgpt.com/backend-api/codex/responses" : endpoint)
        expect(logs[0]).toContain("PAID fallback")
        expect(notices.join(" ")).not.toContain("at-test-paid")
        expect(logs.join(" ")).not.toContain("refresh-test")
        expect(await Bun.file(file).text()).toBe(stored)
        expect(auth.access).toBe("subscription-test")
        if (provider === "anthropic") {
          // The deployed setup has no Anthropic API key. HTTP 200 can still be
          // paid extra usage through the original OAuth login.
          await Bun.write(file, "{}")
          native = true
          expect(await (await loaded.fetch(endpoint, request)).text()).toBe("native-extra-usage")
          expect(requests).toHaveLength(4)
          expect(requests[3].headers.get("authorization")).toBe("Bearer subscription-test")
          expect(requests[3].headers.has("x-api-key")).toBe(false)
          expect(notices.at(-1)).toContain("PAID extra usage")
          expect(logs.at(-1)).toContain("PAID extra usage")
          expect(await Bun.file(file).text()).toBe("{}")
        }
      } finally {
        await hooks?.dispose?.()
        globalThis.fetch = original
      }
    })
  }
})
