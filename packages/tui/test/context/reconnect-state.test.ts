import { expect, test } from "bun:test"
import {
  groupPending,
  mergeTouchedRecord,
  mergeTouchedSessions,
  reconnectRetryable,
} from "../../src/context/reconnect-state"

test("groups pending requests by session so a reconnect clears answered requests", () => {
  expect(
    groupPending([
      { id: "two", sessionID: "a" },
      { id: "one", sessionID: "a" },
      { id: "three", sessionID: "b" },
    ]),
  ).toEqual({
    a: [
      { id: "one", sessionID: "a" },
      { id: "two", sessionID: "a" },
    ],
    b: [{ id: "three", sessionID: "b" }],
  })
  expect(groupPending([])).toEqual({})
})

test("preserves newer status and permission events over a stale reconnect snapshot", () => {
  expect(
    mergeTouchedRecord(
      { active: "busy", answered: "busy", idle: "busy" },
      { active: "idle", answered: "idle" },
      new Set(["active", "idle"]),
    ),
  ).toEqual({ active: "idle", answered: "busy" })
  expect(mergeTouchedRecord({ session: ["old"] }, { session: [] }, new Set(["session"]))).toEqual({ session: [] })
})

test("preserves a newer session update or deletion over a stale session list", () => {
  const snapshot = [
    { id: "a", title: "old" },
    { id: "b", title: "deleted" },
  ]
  const current = [{ id: "a", title: "new" }]
  expect(mergeTouchedSessions(snapshot, current, new Set(["a", "b"]))).toEqual([{ id: "a", title: "new" }])
})

test("does not retry structured auth or missing-resource errors forever", () => {
  expect(reconnectRetryable({ status: 400 })).toBe(false)
  expect(reconnectRetryable({ statusCode: 401 })).toBe(false)
  expect(reconnectRetryable({ response: { status: 403 } })).toBe(false)
  expect(reconnectRetryable({ cause: { status: 404 } })).toBe(false)
  expect(reconnectRetryable({ name: "BadRequest" })).toBe(false)
  expect(reconnectRetryable({ status: 503 })).toBe(true)
  expect(reconnectRetryable(new TypeError("Failed to fetch"))).toBe(true)
})
