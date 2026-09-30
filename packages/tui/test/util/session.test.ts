import { describe, expect, test } from "bun:test"
import { isDefaultTitle, latestQueuedPrompt } from "../../src/util/session"

describe("util.session", () => {
  test("recognizes generated parent and child titles", () => {
    expect(isDefaultTitle("New session - 2026-06-06T12:34:56.789Z")).toBeTrue()
    expect(isDefaultTitle("Child session - 2026-06-06T12:34:56.789Z")).toBeTrue()
    expect(isDefaultTitle("New session - custom")).toBeFalse()
  })

  test("selects only the newest user prompt after a running assistant", () => {
    const active = { id: "assistant", role: "assistant" as const, time: { created: 2 } }
    const first = { id: "first", role: "user" as const, time: { created: 1 } }
    const second = { id: "second", role: "user" as const, time: { created: 3 } }
    expect(latestQueuedPrompt([first, active, second, { ...second, id: "latest", time: { created: 4 } }])?.id).toBe(
      "latest",
    )
    expect(latestQueuedPrompt([first, { ...active, time: { created: 2, completed: 5 } }, second])).toBeUndefined()
    expect(latestQueuedPrompt([first, active, second, { ...active, id: "next" }])).toBeUndefined()
  })
})
