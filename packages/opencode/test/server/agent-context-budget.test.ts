import { expect } from "bun:test"
import { Effect, Layer } from "effect"
import { HttpServer } from "effect/unstable/http"
import { LayerNode } from "@opencode-ai/core/effect/layer-node"
import { createOpencodeClient, type Session, type UserMessage } from "@opencode-ai/sdk"
import { contextBudget } from "@opencode-ai/core/session/context-budget"
import { Session as SessionNs } from "@/session/session"
import { TestInstance } from "../fixture/fixture"
import { testEffect } from "../lib/effect"
import { httpApiLayer } from "./httpapi-layer"
import AgentContextBudget from "../../../../contrib/agent-context-budget/plugin"

const it = testEffect(Layer.mergeAll(LayerNode.compile(SessionNs.node), httpApiLayer))

it.instance(
  "subagent budget plugin persists defaults through real session HTTP routes without touching parent",
  () =>
    Effect.gen(function* () {
      const instance = yield* TestInstance
      const http = yield* HttpServer.HttpServer
      const client = createOpencodeClient({
        baseUrl: HttpServer.formatAddress(http.address),
        directory: instance.directory,
      })
      yield* Effect.promise(async () => {
        const parent = (await client.session.create({ body: { title: "parent" }, throwOnError: true })).data
        const child = (
          await client.session.create({ body: { parentID: parent.id, title: "child" }, throwOnError: true })
        ).data
        try {
          const hooks = await AgentContextBudget({ client })
          const model = { providerID: "test", modelID: "reasoner" }
          const message: UserMessage = {
            id: "msg_test",
            role: "user",
            sessionID: child.id,
            agent: "implementer",
            model,
            time: { created: 1 },
          }
          await hooks.config!({ agent: { implementer: { mode: "subagent", context_budget: "default" } } })
          await hooks["chat.message"]!({ sessionID: child.id }, { message, parts: [] })
          const unchanged: Session & { metadata?: Record<string, unknown> } = (
            await client.session.get({ path: { id: child.id }, throwOnError: true })
          ).data
          expect(contextBudget(unchanged.metadata, model)).toBeUndefined()
          await hooks.config!({ agent: { implementer: { mode: "subagent", context_budget: 256_000 } } })
          await hooks["chat.message"]!({ sessionID: child.id }, { message, parts: [] })
          const saved: Session & { metadata?: Record<string, unknown> } = (
            await client.session.get({ path: { id: child.id }, throwOnError: true })
          ).data
          expect(contextBudget(saved.metadata, model)).toBe(256_000)
          expect(saved.title).toBe("child")
          const original: Session & { metadata?: Record<string, unknown> } = (
            await client.session.get({ path: { id: parent.id }, throwOnError: true })
          ).data
          expect(contextBudget(original.metadata, model)).toBeUndefined()
          expect(original.title).toBe("parent")
        } finally {
          await client.session.delete({ path: { id: parent.id }, throwOnError: true })
        }
      })
    }),
  { git: true },
)
