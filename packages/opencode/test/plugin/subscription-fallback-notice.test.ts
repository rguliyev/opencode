import { expect } from "bun:test"
import path from "node:path"
import { pathToFileURL } from "node:url"
import { Effect } from "effect"
import { LayerNode } from "@opencode-ai/core/effect/layer-node"
import { ProviderV2 } from "@opencode-ai/core/provider"
import { FSUtil } from "@opencode-ai/core/fs-util"
import { Auth } from "../../src/auth"
import { Provider } from "../../src/provider/provider"
import { GlobalBus, type GlobalEvent } from "../../src/bus/global"
import { TestInstance } from "../fixture/fixture"
import { markPluginDependenciesReady } from "../fixture/plugin"
import { testEffect } from "../lib/effect"

const it = testEffect(LayerNode.compile(LayerNode.group([Provider.node, Auth.node, FSUtil.node])))
for (const provider of ["openai", "anthropic"] as const) {
  it.instance(
    `${provider} external wrapper publishes a usage warning through the real SDK and server event bus`,
    () =>
      Effect.gen(function* () {
        const tmp = yield* TestInstance
        const fs = yield* FSUtil.Service
        const auth = yield* Auth.Service
        const providers = yield* Provider.Service
        const original = yield* auth.get(provider)
        const fallback = yield* auth.get(`${provider}-fallback`)
        yield* Effect.addFinalizer(() =>
          Effect.gen(function* () {
            if (original) yield* auth.set(provider, original)
            else yield* auth.remove(provider)
            if (fallback) yield* auth.set(`${provider}-fallback`, fallback)
            else yield* auth.remove(`${provider}-fallback`)
          }).pipe(Effect.orDie),
        )
        yield* auth.set(provider, { type: "oauth", access: "test", refresh: "test-refresh", expires: 9999999999999 })
        yield* auth.remove(`${provider}-fallback`)
        const dir = path.join(tmp.directory, ".opencode")
        yield* Effect.promise(() => markPluginDependenciesReady(dir))
        yield* fs.writeWithDirs(
          path.join(dir, "plugins", "quota.ts"),
          `import { wrapAuth } from ${JSON.stringify(pathToFileURL(path.resolve(import.meta.dir, "../../../../contrib/subscription-fallback/plugin.ts")).href)};
    export default async (input) => wrapAuth({ auth: {
      provider: ${JSON.stringify(provider)}, methods: [],
      loader: async () => ({ fetch: async () => Response.json({ error: { type: ${JSON.stringify(provider === "openai" ? "usage_limit_reached" : "rate_limit_error")} } }, {
        status: 429, headers: { "anthropic-ratelimit-unified-status": "rejected" }
      }) })
    } }, input, ${JSON.stringify(provider)}, ${JSON.stringify(path.join(tmp.directory, "missing-private-credentials.json"))})`,
        )
        const messages: string[] = []
        const listener = (event: GlobalEvent) => {
          if (event.payload.type === "tui.toast.show") messages.push(JSON.stringify(event.payload.properties))
        }
        GlobalBus.on("event", listener)
        yield* Effect.addFinalizer(() =>
          Effect.sync(() => {
            GlobalBus.off("event", listener)
          }),
        )
        const model = yield* providers.getProvider(ProviderV2.ID.make(provider))
        const response = yield* Effect.promise(
          () =>
            model.options.fetch(
              provider === "openai" ? "https://api.openai.com/v1/responses" : "https://api.anthropic.com/v1/messages",
              { method: "POST", body: JSON.stringify({ model: "test", stream: true }) },
            ) as Promise<Response>,
        )
        expect(response.status).toBe(429)
        expect(messages.some((message) => message.includes("NOT started"))).toBe(true)
        expect(messages.some((message) => message.includes(`${provider}: usage warning`))).toBe(true)
      }),
    { git: true },
    30000,
  )
}
