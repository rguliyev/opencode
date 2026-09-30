import { expect, test } from "bun:test"
import { MAX_DIFF_PREVIEW_CHARACTERS, MAX_DIFF_PREVIEW_LINES, oversizedDiff } from "../../src/util/diff-preview"

test("keeps ordinary diffs visible", () => {
  expect(oversizedDiff("@@ -1 +1 @@\n-old\n+new\n")).toBe(false)
  expect(oversizedDiff("x".repeat(MAX_DIFF_PREVIEW_CHARACTERS))).toBe(false)
})

test("omits diffs that exceed the character or line limit", () => {
  expect(oversizedDiff("x".repeat(MAX_DIFF_PREVIEW_CHARACTERS + 1))).toBe(true)
  expect(oversizedDiff("\n".repeat(MAX_DIFF_PREVIEW_LINES))).toBe(true)
})
