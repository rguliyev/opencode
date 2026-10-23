import { expect, test } from "bun:test"
import {
  contextBudget,
  contextBudgets,
  withContextBudget,
  usableContext,
  parseContextBudget,
} from "@opencode-ai/core/session/context-budget"

const model = { providerID: "openai", modelID: "gpt-6.1-sol-fast" }
const limit = { context: 1_050_000, input: 922_000, output: 128_000 }

test("budget preserves the model window and existing headroom; cannot increase capacity", () => {
  expect(usableContext({ limit, reserved: 48_000 })).toBe(874_000)
  expect(usableContext({ limit, reserved: 48_000, budget: 256_000 })).toBe(256_000)
  expect(usableContext({ limit, reserved: 48_000, budget: 2_000_000 })).toBe(874_000)
  expect(limit).toEqual({ context: 1_050_000, input: 922_000, output: 128_000 })
  expect(usableContext({ limit: { context: 200_000, output: 64_000 } })).toBe(168_000)
  expect(usableContext({ limit: { context: 200_000, output: 64_000 }, outputTokenMax: 60_000 })).toBe(140_000)
  expect(usableContext({ limit: { context: 0, output: 0 }, budget: 64_000 })).toBe(0)
})

test("budgets are model-specific, preserve other metadata, and reset without changing the input", () => {
  const original = { owner: "human", contextBudgets: { "other/model": 64_000 } }
  const saved = withContextBudget(original, model, 256_000)
  expect(contextBudget(saved, model)).toBe(256_000)
  expect(saved.owner).toBe("human")
  expect(contextBudget(saved, { providerID: "other", modelID: "model" })).toBe(64_000)
  expect(contextBudget(original, model)).toBeUndefined()
  const reset = withContextBudget(saved, model)
  expect(reset).toEqual(original)
  expect(contextBudget(saved, model)).toBe(256_000)
  expect(contextBudget(JSON.parse(JSON.stringify(saved)), model)).toBe(256_000)
})

test("invalid stored budgets are ignored and invalid edits rejected", () => {
  for (const value of [null, "128000", [], { "openai/gpt-6.1-sol-fast": -1 }])
    expect(contextBudgets({ contextBudgets: value })).toEqual({})
  for (const value of [NaN, Infinity, 0, -1, 31999, 32000.5]) {
    expect(() => withContextBudget({}, model, value)).toThrow()
    expect(usableContext({ limit, budget: value })).toBe(902_000)
  }
})

test("custom budget accepts only explicit token counts and decimal k/m suffixes", () => {
  expect(parseContextBudget("256000")).toBe(256_000)
  expect(parseContextBudget(" 256K ")).toBe(256_000)
  expect(parseContextBudget("0.5m")).toBe(500_000)
  for (const value of ["", "0", "-1", "32k extra", "Infinity", "1e6", "31999", "32,000", "32000.5"])
    expect(parseContextBudget(value)).toBeUndefined()
})
