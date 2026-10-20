type Session = { id: string; parentID?: string }

// iTerm hides tab icons behind its background-output spinner. A paused progress
// indicator takes that slot instead; specify 100 so no stale progress is reused.
// Keep the dot for terminals that support session status but not paused progress.
const indicator = (pending: boolean) =>
  `\x1b]21337;indicator=${pending ? "#ffa500" : ""}\x07\x1b]9;4;${pending ? "4;100" : "0"}\x07`

export function hasPendingPermission(
  sessionID: string,
  sessions: readonly Session[],
  permissions: Record<string, readonly unknown[]>,
) {
  const rootID = sessions.find((session) => session.id === sessionID)?.parentID ?? sessionID
  if (permissions[sessionID]?.length) return true
  return sessions.some(
    (session) => (session.id === rootID || session.parentID === rootID) && !!permissions[session.id]?.length,
  )
}

export function createItermPermissionIndicator(input: {
  env: Partial<Record<"TERM_PROGRAM" | "TMUX" | "STY", string>>
  isTTY: boolean | undefined
  write: (value: string) => void
}) {
  const enabled = input.isTTY && input.env.TERM_PROGRAM === "iTerm.app" && !input.env.TMUX && !input.env.STY
  let active = false

  return {
    set(pending: boolean) {
      if (!enabled || active === pending) return
      active = pending
      input.write(indicator(pending))
    },
    dispose() {
      if (!active) return
      active = false
      input.write(indicator(false))
    },
  }
}
