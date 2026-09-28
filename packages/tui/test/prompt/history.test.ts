import { describe, expect, test } from "bun:test"
import {
  isDuplicateEntry,
  MAX_HISTORY_ENTRIES,
  parsePromptHistory,
  promptHistoryForSession,
  promptsFromMessages,
  retainPromptHistory,
  type PromptInfo,
} from "../../src/prompt/history"

const entry = (input: string, parts: PromptInfo["parts"] = []): PromptInfo => ({ input, parts })

describe("prompt history", () => {
  test("recovers valid JSONL entries around corruption", () => {
    expect(parsePromptHistory(`${JSON.stringify(entry("one"))}\nnot-json\n${JSON.stringify(entry("two"))}\n`)).toEqual([
      entry("one"),
      entry("two"),
    ])
  })

  test("retains only the newest entries", () => {
    const input = Array.from({ length: MAX_HISTORY_ENTRIES + 5 }, (_, index) =>
      JSON.stringify(entry(String(index))),
    ).join("\n")
    const result = parsePromptHistory(input)
    expect(result).toHaveLength(MAX_HISTORY_ENTRIES)
    expect(result[0]?.input).toBe("5")
  })

  test("retains 50 prompts per session instead of 50 globally", () => {
    const entries = Array.from({ length: MAX_HISTORY_ENTRIES + 5 }, (_, index) => [
      { ...entry(`alpha ${index}`), sessionID: "ses_alpha" },
      { ...entry(`beta ${index}`), sessionID: "ses_beta" },
    ]).flat()
    const retained = retainPromptHistory(entries)
    expect(retained).toHaveLength(MAX_HISTORY_ENTRIES * 2)
    expect(retained.filter((item) => item.sessionID === "ses_alpha").at(0)?.input).toBe("alpha 5")
    expect(retained.filter((item) => item.sessionID === "ses_beta").at(0)?.input).toBe("beta 5")
  })

  test("only recalls prompts from the active session", () => {
    const entries = [
      { ...entry("alpha"), sessionID: "ses_alpha" },
      { ...entry("beta"), sessionID: "ses_beta" },
      entry("legacy home prompt"),
    ]
    expect(promptHistoryForSession(entries, "ses_alpha").map((item) => item.input)).toEqual(["alpha"])
    expect(promptHistoryForSession(entries, "ses_beta").map((item) => item.input)).toEqual(["beta"])
    expect(promptHistoryForSession(entries, undefined).map((item) => item.input)).toEqual(["legacy home prompt"])
  })

  test("restores old session prompts from server messages without losing richer local entries", () => {
    const server = promptsFromMessages([
      { info: { role: "user" }, parts: [{ type: "text", text: "first" }] },
      { info: { role: "assistant" }, parts: [{ type: "text", text: "answer" }] },
      {
        info: { role: "user" },
        parts: [
          { type: "text", text: "internal context", synthetic: true },
          { type: "text", text: "second" },
        ],
      },
    ])
    expect(server.map((item) => item.input)).toEqual(["first", "second"])
    const local = [{ ...entry("second", [{ type: "file", mime: "image/png", url: "data:image/png;base64,AAA" }]), sessionID: "ses_alpha" }]
    const restored = promptHistoryForSession(local, "ses_alpha", server)
    expect(restored.map((item) => item.input)).toEqual(["first", "second"])
    expect(restored[1]?.parts).toEqual(local[0].parts)
  })

  test("dedupes only identical consecutive entries", () => {
    expect(isDuplicateEntry(undefined, entry("hello"))).toBe(false)
    expect(isDuplicateEntry(entry("hello"), entry("hello"))).toBe(true)
    expect(isDuplicateEntry(entry("foo"), entry("bar"))).toBe(false)
    expect(isDuplicateEntry({ ...entry("ls"), mode: "normal" }, { ...entry("ls"), mode: "shell" })).toBe(false)
  })

  test("does not dedupe entries with different parts", () => {
    const a = entry("describe this", [
      { type: "file", mime: "image/png", filename: "a.png", url: "data:image/png;base64,AAA" },
    ])
    const b = entry("describe this", [
      { type: "file", mime: "image/png", filename: "b.png", url: "data:image/png;base64,BBB" },
    ])
    expect(isDuplicateEntry(a, b)).toBe(false)
  })
})
