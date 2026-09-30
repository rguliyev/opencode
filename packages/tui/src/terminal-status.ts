type Session = { id: string; parentID?: string }

const indicator = (color: string) => `\x1b]21337;indicator=${color}\x07`

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
      input.write(indicator(pending ? "#ffa500" : ""))
    },
    dispose() {
      if (!active) return
      active = false
      input.write(indicator(""))
    },
  }
}
