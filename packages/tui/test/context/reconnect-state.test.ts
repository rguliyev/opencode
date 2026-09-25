import { expect, test } from "bun:test"
import {
  groupPending,
  mergeTouchedPending,
  mergeTouchedRecord,
  mergeTouchedSessions,
  reconnectRetryable,
  touchPending,
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

test("initial attach snapshots group permission and question requests that predate the event stream", () => {
  const permission = { id: "permission-1", sessionID: "session-1" }
  const question = { id: "question-1", sessionID: "session-1" }

  expect(mergeTouchedPending([permission], {}, new Map())).toEqual({ "session-1": [permission] })
  expect(mergeTouchedPending([question], {}, new Map())).toEqual({ "session-1": [question] })
})

test("a reply or new request received during a snapshot beats stale pending data", () => {
  const stale = { id: "answered", sessionID: "session-1" }
  const recent = { id: "new", sessionID: "session-2" }
  const touched = new Map<string, Set<string>>()
  touchPending(touched, stale.sessionID, stale.id)
  touchPending(touched, recent.sessionID, recent.id)
  expect(mergeTouchedPending([stale], { "session-2": [recent] }, touched)).toEqual({ "session-2": [recent] })
})

test("a new request in the same session does not hide an older pending permission or question", () => {
  const older = { id: "permission-1", sessionID: "session-1", value: "snapshot" }
  const newer = { id: "permission-2", sessionID: "session-1", value: "event" }
  const touched = new Map<string, Set<string>>()
  touchPending(touched, newer.sessionID, newer.id)
  expect(mergeTouchedPending([older], { "session-1": [newer] }, touched)).toEqual({
    "session-1": [older, newer],
  })

  const olderQuestion = { id: "question-1", sessionID: "session-1", value: "snapshot" }
  const question = { id: "question-2", sessionID: "session-1", value: "event" }
  const questions = new Map<string, Set<string>>()
  touchPending(questions, question.sessionID, question.id)
  expect(mergeTouchedPending([olderQuestion], { "session-1": [question] }, questions)).toEqual({
    "session-1": [olderQuestion, question],
  })
})

test("a reply removes only its request, not other pending requests in that session", () => {
  const answered = { id: "permission-1", sessionID: "session-1" }
  const waiting = { id: "permission-2", sessionID: "session-1" }
  const touched = new Map<string, Set<string>>()
  touchPending(touched, answered.sessionID, answered.id)
  expect(mergeTouchedPending([answered, waiting], { "session-1": [waiting] }, touched)).toEqual({
    "session-1": [waiting],
  })
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
