import { describe, expect, test } from "bun:test"
import {
  createDialogSessionListQuery,
  loadDialogSessionList,
  selectDialogSessions,
} from "../../src/component/dialog-session-list"
import type { Session } from "@opencode-ai/sdk/v2"

describe("dialog session list", () => {
  const session = (id: string, title: string): Session => ({
    id,
    title,
    slug: id,
    projectID: "project",
    directory: "/repo",
    version: "test",
    time: { created: 1, updated: 1 },
  })

  test("keeps prompt matches even when the title does not match and the cache has no excerpt", () => {
    const cached = session("ses_root", "Tango infrastructure")
    const match = {
      ...cached,
      searchMatch: { kind: "prompt" as const, sessionID: cached.id, excerpt: "Reclaim BPF memory", time: 1 },
    }
    const result = selectDialogSessions({
      search: "BPF",
      remote: { query: "BPF", sessions: [match] },
      fallback: [],
      synced: [cached],
      extra: [],
    })
    expect(result).toHaveLength(1)
    expect(result[0].searchMatch?.excerpt).toBe("Reclaim BPF memory")
  })

  test("does not show stale content hits for a different query", () => {
    const cached = session("ses_root", "Tango infrastructure")
    const result = selectDialogSessions({
      search: "disk",
      remote: { query: "BPF", sessions: [cached] },
      fallback: [cached],
      synced: [cached],
      extra: [cached.id],
    })
    expect(result).toEqual([])
  })

  test("does not reuse content hits from a different path filter", () => {
    const cached = session("ses_root", "Tango infrastructure")
    expect(
      selectDialogSessions({
        search: "BPF",
        filter: { path: "new" },
        remote: { query: "BPF", filter: { path: "old" }, sessions: [cached] },
        fallback: [],
        synced: [],
        extra: [],
      }),
    ).toEqual([])
  })

  test("retains offline title matching and de-duplicates pinned/current extras", () => {
    const cached = session("ses_root", "BPF investigation")
    expect(
      selectDialogSessions({ search: "bpf", fallback: [cached], synced: [cached], extra: [cached.id, cached.id] }).map(
        (x) => x.id,
      ),
    ).toEqual([cached.id])
    expect(
      selectDialogSessions({
        search: "absent",
        remote: { query: "absent", sessions: [] },
        fallback: [cached],
        synced: [cached],
        extra: [cached.id],
      }),
    ).toEqual([])
  })

  test("requests root sessions for the default browse list", () => {
    expect(createDialogSessionListQuery({ filter: { path: "packages/tui" } })).toEqual({
      roots: true,
      limit: 100,
      path: "packages/tui",
    })
  })

  test("requests root sessions for search results", () => {
    expect(createDialogSessionListQuery({ search: " deploy ", filter: { scope: "project" } })).toEqual({
      roots: true,
      limit: 30,
      search: "deploy",
      scope: "project",
    })
  })

  test("keeps the cache usable while the root request is pending", async () => {
    let resolve!: (result: { data: string[] }) => void
    const pending = loadDialogSessionList<string>({
      filter: {},
      list: () => new Promise((done) => (resolve = done)),
    })

    expect(await Promise.race([pending, Promise.resolve("pending")])).toBe("pending")
    resolve({ data: ["root"] })
    expect(await pending).toEqual(["root"])
  })

  test("falls back when the root request returns an error response", async () => {
    expect(await loadDialogSessionList({ filter: {}, list: async () => ({}) })).toBeUndefined()
  })

  test("falls back when the root request rejects", async () => {
    expect(
      await loadDialogSessionList({
        filter: {},
        list: () => Promise.reject(new Error("offline")),
      }),
    ).toBeUndefined()
  })
})
