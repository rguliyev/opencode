import { expect, test } from "bun:test"
import type { Message, Part } from "@opencode-ai/sdk/v2"
import {
  MESSAGE_PAGE_SIZE,
  mergeHistoryParts,
  mergeMessageHistory,
  readMessageWindow,
} from "../../src/context/message-history"

function message(index: number, role: "user" | "assistant" = "assistant"): Message {
  const common = { id: `msg_${String(index).padStart(5, "0")}`, sessionID: "ses_history", time: { created: index } }
  if (role === "user")
    return { ...common, role, agent: "orchestrator", model: { providerID: "openai", modelID: "test" } }
  return {
    ...common,
    role,
    parentID: "msg_00000",
    modelID: "test",
    providerID: "openai",
    mode: "build",
    agent: "orchestrator",
    path: { cwd: "/work", root: "/work" },
    cost: 0,
    tokens: { input: 0, output: 0, reasoning: 0, cache: { read: 0, write: 0 } },
  }
}
const prompts = new Set([0, 20, 40, 60, 70, 85, 95, 105, 125, 135, 145, 155, 165])
const transcript = Array.from({ length: 174 }, (_, index) => message(index, prompts.has(index) ? "user" : "assistant"))
const visiblePrompts = (messages: Message[]) => messages.filter((item) => item.id < "msg_00135" && item.role === "user")

test("older pages restore all nine non-reverted prompts instead of only four", () => {
  const initial = transcript.slice(-MESSAGE_PAGE_SIZE)
  expect(visiblePrompts(initial)).toHaveLength(4)
  const merged = mergeMessageHistory(transcript.slice(0, -MESSAGE_PAGE_SIZE), initial, new Set(), true)
  expect(merged).toEqual(transcript)
  expect(visiblePrompts(merged)).toHaveLength(9)
  expect(merged.filter((item) => item.role === "user")).toHaveLength(13)
  expect(merged.filter((item) => item.id >= "msg_00135")).toHaveLength(39)
})
test("overlapping pages deduplicate and new live messages retain earlier prompts", () => {
  expect(mergeMessageHistory(transcript.slice(0, 100), transcript.slice(74), new Set(), true)).toEqual(transcript)
  const live = message(174, "user")
  const merged = mergeMessageHistory([], [...transcript, live], new Set([live.id]), true)
  expect(merged).toHaveLength(175)
  expect(merged[0]).toEqual(transcript[0])
})
test("a reconnect snapshot respects live updates and removals", () => {
  const changed = { ...message(90), agent: "new-agent" }
  const live = message(174, "user")
  const current = transcript
    .filter((item) => item.id !== "msg_00080")
    .map((item) => (item.id === changed.id ? changed : item))
  current.push(live)
  const merged = mergeMessageHistory(transcript, current, new Set(["msg_00080", changed.id, live.id]))
  expect(merged.find((item) => item.id === "msg_00080")).toBeUndefined()
  expect(merged.find((item) => item.id === changed.id)).toEqual(changed)
  expect(merged.at(-1)).toEqual(live)
  expect(visiblePrompts(merged)).toHaveLength(9)
})
test("fresh attach reads one bounded page, reconnect restores the loaded window", async () => {
  const requests: Array<string | undefined> = []
  const load = async (before?: string) => {
    requests.push(before)
    const end = before ? Number(before) : transcript.length
    const start = Math.max(0, end - MESSAGE_PAGE_SIZE)
    return { data: transcript.slice(start, end).map((info) => ({ info })), cursor: start ? String(start) : undefined }
  }
  const initial = await readMessageWindow(load)
  expect(initial.data).toHaveLength(100)
  expect(initial.cursor).toBe("74")
  expect(requests).toEqual([undefined])
  requests.length = 0
  const reconnected = await readMessageWindow(load, transcript[0].id)
  expect(reconnected.data.map((item) => item.info)).toEqual(transcript)
  expect(reconnected.cursor).toBeUndefined()
  expect(requests).toEqual([undefined, "74"])
})
test("reconnect stops at the previously loaded boundary, not the entire transcript", async () => {
  const all = Array.from({ length: 350 }, (_, index) => ({ info: message(index) }))
  let requests = 0
  const loaded = await readMessageWindow(async (before) => {
    requests++
    const end = before ? Number(before) : all.length
    return { data: all.slice(Math.max(0, end - 100), end), cursor: end > 100 ? String(end - 100) : undefined }
  }, message(175).id)
  expect(requests).toBe(2)
  expect(loaded.data).toHaveLength(200)
  expect(loaded.cursor).toBe("150")
})
test("empty histories terminate and non-advancing cursors fail instead of hanging", async () => {
  expect(await readMessageWindow(async () => ({ data: [] }))).toEqual({ data: [], cursor: undefined })
  await readMessageWindow(async () => ({ data: [{ info: message(9) }], cursor: "same" }), message(0).id).then(
    () => {
      throw new Error("Expected a cursor error")
    },
    (error: Error) => expect(error.message).toContain("cursor did not advance"),
  )
})
test("parts preserve concurrent text updates and remove parts deleted during hydration", () => {
  const text: Part = { id: "prt_text", sessionID: "ses_history", messageID: "msg_00000", type: "text", text: "hello" }
  const changed = { ...text, text: "hello world" }
  expect(mergeHistoryParts([text], [changed], new Set([text.id]))).toEqual([changed])
  expect(mergeHistoryParts([text], [], new Set([text.id]))).toEqual([])
  expect(mergeHistoryParts([{ ...text, text: "" }], [text], new Set())).toEqual([text])
})
