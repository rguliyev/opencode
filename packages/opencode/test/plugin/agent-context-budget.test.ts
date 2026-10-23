import { expect, test } from "bun:test"
import { Schema } from "effect"
import { createOpencodeClient, type UserMessage } from "@opencode-ai/sdk"
import { ConfigAgentV1 } from "@opencode-ai/core/v1/config/agent"
import { contextBudget, usableContext, withContextBudget } from "@opencode-ai/core/session/context-budget"
import AgentContextBudget from "../../../../contrib/agent-context-budget/plugin"

const model = { providerID: "test", modelID: "reasoner" }
async function setup(value: unknown = 256_000, metadata: Record<string, unknown> = {}) {
  const state = { metadata, parentID: "ses_parent", writes: 0, reads: 0, fail: false }
  const client = createOpencodeClient({
    baseUrl: "http://test",
    fetch: async (request) => {
      if (request.method === "GET") state.reads++
      else if (request.method === "PATCH") {
        if (state.fail) return Response.json({ message: "save failed" }, { status: 500 })
        state.writes++
        state.metadata = (await request.json()).metadata
      } else throw new Error(`Unexpected ${request.method}`)
      return Response.json({ id: "ses_child", parentID: state.parentID, metadata: state.metadata })
    },
  })
  const hooks = await AgentContextBudget({ client })
  const decoded = Schema.decodeUnknownSync(ConfigAgentV1.Info)({ mode: "subagent", context_budget: value })
  const config = {
    agent: { implementer: { mode: "subagent" as const, context_budget: value, options: decoded.options } },
  }
  await hooks.config!(config)
  const message: UserMessage = {
    id: "msg_user",
    sessionID: "ses_child",
    role: "user",
    agent: "implementer",
    model,
    time: { created: 1 },
  }
  const send = (change: Partial<UserMessage> = {}) =>
    hooks["chat.message"]!({ sessionID: "ses_child" }, { message: { ...message, ...change }, parts: [] })
  return { hooks, state, config, send }
}

test("default keeps native capacity and performs no session mutations", async () => {
  const fixture = await setup("default")
  await fixture.send()
  expect(fixture.state.reads).toBe(0)
  expect(fixture.state.writes).toBe(0)
  expect(fixture.state.metadata).toEqual({})
  expect(fixture.config.agent.implementer.options?.context_budget).toBeUndefined()
  expect(usableContext({ limit: { context: 1_050_000, input: 922_000, output: 128_000 }, reserved: 48_000 })).toBe(
    874_000,
  )
})

test("numeric config reaches persisted metadata through the real SDK and caps compaction without changing the model", async () => {
  const fixture = await setup(256_000, { owner: "user", contextBudgets: { "other/model": 64_000 } })
  await Promise.all([fixture.send(), fixture.send()])
  expect(fixture.state.writes).toBe(1)
  expect(contextBudget(fixture.state.metadata, model)).toBe(256_000)
  expect(fixture.state.metadata.owner).toBe("user")
  expect(contextBudget(fixture.state.metadata, { providerID: "other", modelID: "model" })).toBe(64_000)
  const limit = { context: 200_000, output: 32_000 }
  expect(usableContext({ limit, budget: contextBudget(fixture.state.metadata, model) })).toBe(168_000)
  expect(limit.context).toBe(200_000)
})

test("manual selection and manual reset survive subsequent prompts and plugin reload", async () => {
  const fixture = await setup(256_000, withContextBudget({}, model, 64_000))
  await fixture.send()
  expect(contextBudget(fixture.state.metadata, model)).toBe(64_000)
  fixture.state.metadata = withContextBudget(fixture.state.metadata, model)
  await fixture.send()
  expect(contextBudget(fixture.state.metadata, model)).toBeUndefined()
  const reloaded = await setup(128_000, fixture.state.metadata)
  await reloaded.send()
  expect(reloaded.state.writes).toBe(0)
  expect(contextBudget(reloaded.state.metadata, model)).toBeUndefined()
})

test("parent sessions, unconfigured and disabled agents are unchanged", async () => {
  const fixture = await setup()
  fixture.state.parentID = ""
  await fixture.send()
  expect(fixture.state.writes).toBe(0)
  fixture.state.parentID = "ses_parent"
  await fixture.send({ agent: "orchestrator" })
  expect(fixture.state.writes).toBe(0)
  await fixture.hooks.config!({ agent: { implementer: { mode: "subagent", disable: true, context_budget: 128_000 } } })
  await fixture.send()
  expect(fixture.state.writes).toBe(0)
})

test("defaults are scoped by agent and model", async () => {
  const fixture = await setup()
  await fixture.hooks.config!({
    agent: {
      implementer: { mode: "subagent", context_budget: 256_000 },
      reviewer: { mode: "subagent", context_budget: 128_000 },
    },
  })
  await fixture.send()
  const alternate = { ...model, modelID: "other" }
  await fixture.send({ agent: "reviewer", model: alternate })
  expect(contextBudget(fixture.state.metadata, model)).toBe(256_000)
  expect(contextBudget(fixture.state.metadata, alternate)).toBe(128_000)
})

test("invalid configuration and failed writes fail visibly and retry safely", async () => {
  for (const invalid of [-1, 0, 31_999, 32_000.5, "256k", "bad", null]) {
    const fixture = await setup(invalid)
    await expect(fixture.send()).rejects.toThrow("context_budget")
    expect(fixture.state.writes).toBe(0)
  }
  const fixture = await setup()
  fixture.state.fail = true
  await expect(fixture.send()).rejects.toBeDefined()
  expect(fixture.state.metadata).toEqual({})
  fixture.state.fail = false
  await fixture.send()
  expect(contextBudget(fixture.state.metadata, model)).toBe(256_000)
})
