import { expect, test } from "bun:test"
import { createItermPermissionIndicator, hasPendingPermission } from "../src/terminal-status"

test("permission status includes the session and its subagents, but not other sessions", () => {
  const sessions = [
    { id: "root" },
    { id: "child", parentID: "root" },
    { id: "other" },
  ]
  expect(hasPendingPermission("root", sessions, { child: [{}] })).toBe(true)
  expect(hasPendingPermission("child", sessions, { root: [{}] })).toBe(true)
  expect(hasPendingPermission("root", sessions, { other: [{}] })).toBe(false)
  expect(hasPendingPermission("missing", sessions, { missing: [{}] })).toBe(true)
  expect(hasPendingPermission("root", sessions, { child: [] })).toBe(false)
})

test("iTerm permission indicator overrides activity with paused progress and clears both indicators", () => {
  const writes: string[] = []
  const status = createItermPermissionIndicator({
    env: { TERM_PROGRAM: "iTerm.app" },
    isTTY: true,
    write: (value) => writes.push(value),
  })
  status.set(false)
  status.set(true)
  status.set(true)
  status.set(false)
  status.set(true)
  status.dispose()
  status.dispose()
  expect(writes).toEqual([
    "\x1b]21337;indicator=#ffa500\x07\x1b]9;4;4;100\x07",
    "\x1b]21337;indicator=\x07\x1b]9;4;0\x07",
    "\x1b]21337;indicator=#ffa500\x07\x1b]9;4;4;100\x07",
    "\x1b]21337;indicator=\x07\x1b]9;4;0\x07",
  ])
})

test("subagent permissions override the spinner without waiting for terminal focus", () => {
  const writes: string[] = []
  const status = createItermPermissionIndicator({
    env: { TERM_PROGRAM: "iTerm.app" },
    isTTY: true,
    write: (value) => writes.push(value),
  })
  const sessions = [{ id: "root" }, { id: "child", parentID: "root" }]
  status.set(hasPendingPermission("root", sessions, { child: [{}] }))
  expect(writes).toEqual(["\x1b]21337;indicator=#ffa500\x07\x1b]9;4;4;100\x07"])

  // Another permission remains: do not clear the warning after just one answer.
  status.set(hasPendingPermission("root", sessions, { root: [{}], child: [] }))
  expect(writes).toHaveLength(1)
  status.set(hasPendingPermission("root", sessions, { root: [], child: [] }))
  expect(writes[1]).toBe("\x1b]21337;indicator=\x07\x1b]9;4;0\x07")
  status.dispose()
  expect(writes).toHaveLength(2)
})

test("an idle client neither sets nor clears another program's progress indicator", () => {
  const writes: string[] = []
  const status = createItermPermissionIndicator({
    env: { TERM_PROGRAM: "iTerm.app" },
    isTTY: true,
    write: (value) => writes.push(value),
  })
  status.set(false)
  status.dispose()
  expect(writes).toEqual([])
})

test("non-iTerm, multiplexed, and non-TTY sessions do not receive iTerm control codes", () => {
  for (const input of [
    { env: {}, isTTY: true },
    { env: { TERM_PROGRAM: "iTerm.app", TMUX: "/tmp/tmux" }, isTTY: true },
    { env: { TERM_PROGRAM: "iTerm.app", STY: "screen" }, isTTY: true },
    { env: { TERM_PROGRAM: "iTerm.app" }, isTTY: false },
  ]) {
    const writes: string[] = []
    const status = createItermPermissionIndicator({ ...input, write: (value) => writes.push(value) })
    status.set(true)
    status.dispose()
    expect(writes).toEqual([])
  }
})
