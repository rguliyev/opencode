import { describe, expect } from "bun:test"
import { Effect, Layer } from "effect"
import { eq, sql } from "drizzle-orm"
import { HttpServer } from "effect/unstable/http"
import { LayerNode } from "@opencode-ai/core/effect/layer-node"
import { Database } from "@opencode-ai/core/database/database"
import { MessageTable, PartTable, SessionTable } from "@opencode-ai/core/session/sql"
import { SessionProjector } from "@opencode-ai/core/session/projector"
import { createOpencodeClient } from "@opencode-ai/sdk/v2"
import { Session } from "@/session/session"
import { SessionSearch } from "@/session/search"
import { MessageID, PartID, SessionID } from "@/session/schema"
import { provideInstance, TestInstance, tmpdirScoped } from "../fixture/fixture"
import { testEffect } from "../lib/effect"
import { httpApiLayer } from "./httpapi-layer"

const it = testEffect(
  Layer.mergeAll(
    LayerNode.compile(LayerNode.group([Database.node, Session.node, SessionProjector.node])),
    httpApiLayer,
  ),
)
const withSession = (input?: Parameters<Session.Interface["create"]>[0]) =>
  Effect.acquireRelease(Session.use.create(input), (session) => Session.use.remove(session.id).pipe(Effect.ignore))

// Search operates on stored history, independent of an active model run. Persist
// only the message fields inspected by search; never call an LLM in these tests.
function history(
  sessionID: SessionID,
  text: string,
  options: {
    role?: "user" | "assistant"
    type?: "text" | "tool"
    synthetic?: boolean
    ignored?: boolean
    time?: number
  } = {},
) {
  return Effect.gen(function* () {
    const { db } = yield* Database.Service
    const id = MessageID.ascending()
    const time = options.time ?? Date.now()
    yield* db.insert(MessageTable).values({
      id,
      session_id: sessionID,
      time_created: time,
      time_updated: time,
      data: sql`${JSON.stringify({ role: options.role ?? "user", time: { created: time } })}`,
    })
    yield* db.insert(PartTable).values({
      id: PartID.ascending(),
      message_id: id,
      session_id: sessionID,
      time_created: time,
      time_updated: time,
      data: sql`${JSON.stringify({ type: options.type ?? "text", text, synthetic: options.synthetic, ignored: options.ignored })}`,
    })
    return id
  })
}

describe("session content search", () => {
  it.instance(
    "finds old prompts before applying the result limit and returns a bounded excerpt",
    () =>
      Effect.gen(function* () {
        const root = yield* withSession({ title: "Tango infrastructure" })
        const id = yield* history(root.id, "x".repeat(400) + " reclaim BPF memory " + "y".repeat(400), { time: 1 })
        for (let i = 0; i < 110; i++) yield* history(root.id, "unrelated newer prompt", { time: i + 2 })
        yield* withSession({ title: "unrelated newer session" })
        const result = yield* Session.use.list({ search: " bPf ", roots: true, limit: 1 })
        expect(result.map((x) => x.id)).toEqual([root.id])
        expect(result[0].searchMatch).toMatchObject({ kind: "prompt", sessionID: root.id, messageID: id, time: 1 })
        expect(result[0].searchMatch!.excerpt).toContain("BPF memory")
        expect(result[0].searchMatch!.excerpt.length).toBeLessThanOrEqual(240)
        expect(yield* Session.use.get(root.id)).not.toHaveProperty("searchMatch")
      }),
    { git: true },
  )

  it.instance(
    "groups nested subagent titles and prompts under their root without duplicates",
    () =>
      Effect.gen(function* () {
        const root = yield* withSession({ title: "Deployment plan" })
        const child = yield* withSession({ parentID: root.id, title: "Cilium BPF leak" })
        const nested = yield* withSession({ parentID: child.id, title: "Kernel verifier details" })
        yield* history(nested.id, "debug kernel verifier failure diagnostic-only")
        expect((yield* Session.use.list({ search: "diagnostic-only", roots: true }))[0].searchMatch).toMatchObject({
          kind: "prompt",
          sessionID: nested.id,
        })
        expect((yield* Session.use.list({ search: "BPF", roots: true })).map((x) => x.id)).toEqual([root.id])
        const result = yield* Session.use.list({ search: "verifier", roots: true })
        expect(result.map((x) => x.id)).toEqual([root.id])
        expect(result[0].searchMatch).toMatchObject({ sessionID: nested.id, agent: "subagent" })
        expect((yield* Session.use.list({ search: "verifier", roots: false })).map((x) => x.id)).toEqual([nested.id])
        yield* history(root.id, "verifier issue in my own prompt", { time: Date.now() + 1 })
        expect((yield* Session.use.list({ search: "verifier", roots: true }))[0].searchMatch!.sessionID).toBe(root.id)
      }),
    { git: true },
  )

  it.instance(
    "matches literal punctuation and excludes tools, assistant output, synthetic and ignored text",
    () =>
      Effect.gen(function* () {
        const root = yield* withSession({ title: "literal 100%_done" })
        yield* history(root.id, "hidden-only", { role: "assistant" })
        yield* history(root.id, "hidden-only", { type: "tool" })
        yield* history(root.id, "hidden-only", { synthetic: true })
        yield* history(root.id, "hidden-only", { ignored: true })
        expect(yield* Session.use.list({ search: "hidden-only", roots: true })).toEqual([])
        expect((yield* Session.use.list({ search: "%_", roots: true })).map((x) => x.id)).toEqual([root.id])
        expect(yield* Session.use.list({ search: "100%missing", roots: true })).toEqual([])
        const browse = yield* Session.use.list({ search: "  ", roots: true })
        expect(browse[0].searchMatch).toBeUndefined()
        expect(
          SessionSearch.decode(JSON.stringify({ kind: "title", sessionID: root.id, excerpt: "a\u001bb\nc", time: 1 }))!
            .excerpt,
        ).toBe("a b c")
      }),
    { git: true },
  )

  it.instance(
    "respects project boundaries even for a cross-project parent reference",
    () =>
      Effect.gen(function* () {
        const root = yield* withSession({ title: "Local" })
        const second = yield* tmpdirScoped({ git: true })
        const outside = yield* withSession({ title: "Foreign needle" }).pipe(provideInstance(second))
        const { db } = yield* Database.Service
        yield* db.update(SessionTable).set({ parent_id: root.id }).where(eq(SessionTable.id, outside.id))
        yield* history(outside.id, "Foreign needle prompt")
        expect(yield* Session.use.list({ search: "needle", roots: true })).toEqual([])
      }),
    { git: true },
  )

  it.instance(
    "returns content matches and excerpts through the real generated SDK HTTP route",
    () =>
      Effect.gen(function* () {
        const instance = yield* TestInstance
        const server = yield* HttpServer.HttpServer
        const root = yield* withSession({ title: "Not a title match" })
        yield* history(root.id, "How do I reclaim BPF memory?")
        const client = createOpencodeClient({
          baseUrl: HttpServer.formatAddress(server.address),
          directory: instance.directory,
        })
        const response = yield* Effect.promise(() => client.session.list({ search: "BPF", roots: true }))
        expect(response.response.status).toBe(200)
        expect(response.data).toHaveLength(1)
        expect(response.data![0]).toMatchObject({
          id: root.id,
          searchMatch: { kind: "prompt", excerpt: "How do I reclaim BPF memory?" },
        })
        const global = yield* Session.use.listGlobal({ search: "BPF", roots: true })
        expect(global.find((x) => x.id === root.id)?.searchMatch?.kind).toBe("prompt")
      }),
    { git: true },
  )
})
