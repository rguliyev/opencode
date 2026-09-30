import { expect, test } from "bun:test"
import type { Part } from "@opencode-ai/sdk/v2"
import { partForDisplay } from "../../src/context/part-display"

const patch = "-generated content\n".repeat(18_840)
const part: Part = {
  id: "prt_test",
  sessionID: "ses_test",
  messageID: "msg_test",
  type: "tool",
  callID: "call_test",
  tool: "apply_patch",
  state: {
    status: "completed",
    input: {},
    output: "D generated.js",
    title: "D generated.js",
    time: { start: 1, end: 2 },
    metadata: {
      diff: patch,
      files: [
        { type: "delete", filePath: "/tmp/generated.js", relativePath: "generated.js", patch, deletions: 18_840 },
      ],
    },
  },
}

test("compacts large completed deletion metadata without changing the server part", () => {
  const display = partForDisplay(part)
  if (display.type !== "tool" || display.state.status !== "completed") throw new Error("expected completed tool")
  expect(display.state.metadata.diff).toBe("")
  expect(display.state.metadata.files).toEqual([
    { type: "delete", filePath: "/tmp/generated.js", relativePath: "generated.js", patch: "", deletions: 18_840 },
  ])
  expect(part.state.status === "completed" && part.state.metadata.diff).toBe(patch)
})

test("retains small deletions and large non-deletion patches", () => {
  if (part.type !== "tool" || part.state.status !== "completed") throw new Error("expected completed tool")
  const small = {
    ...part,
    state: {
      ...part.state,
      metadata: { ...part.state.metadata, diff: "-old\n", files: [{ type: "delete", patch: "-old\n" }] },
    },
  } as Part
  expect(partForDisplay(small)).toBe(small)
  const update = {
    ...part,
    state: { ...part.state, metadata: { ...part.state.metadata, files: [{ type: "update", patch }] } },
  } as Part
  expect(partForDisplay(update)).toBe(update)
})

test("compacts large deletions when the server omits the duplicate combined diff", () => {
  if (part.type !== "tool" || part.state.status !== "completed") throw new Error("expected completed tool")
  const deduplicated = { ...part, state: { ...part.state, metadata: { ...part.state.metadata, diff: "" } } } as Part
  const display = partForDisplay(deduplicated)
  if (display.type !== "tool" || display.state.status !== "completed") throw new Error("expected completed tool")
  expect(display.state.metadata.files).toEqual([
    { type: "delete", filePath: "/tmp/generated.js", relativePath: "generated.js", patch: "", deletions: 18_840 },
  ])
})
