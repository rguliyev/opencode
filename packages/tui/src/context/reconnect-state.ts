export function groupPending<T extends { id: string; sessionID: string }>(items: T[]) {
  const grouped: Record<string, T[]> = {}
  for (const item of items) (grouped[item.sessionID] ??= []).push(item)
  for (const requests of Object.values(grouped)) requests.sort((a, b) => a.id.localeCompare(b.id))
  return grouped
}

export function reconnectRetryable(error: unknown) {
  const value = error !== null && typeof error === "object" ? error : undefined
  const response =
    value && "response" in value && value.response && typeof value.response === "object" ? value.response : undefined
  const cause = value && "cause" in value && value.cause && typeof value.cause === "object" ? value.cause : undefined
  const status = [
    value && "status" in value ? value.status : undefined,
    value && "statusCode" in value ? value.statusCode : undefined,
    response && "status" in response ? response.status : undefined,
    cause && "status" in cause ? cause.status : undefined,
  ]
    .map(Number)
    .find(Number.isFinite)
  if (status !== undefined && status >= 400 && status < 500) return false
  const name = value && "name" in value ? String(value.name) : value && "_tag" in value ? String(value._tag) : ""
  if (/BadRequest|Unauthorized|Forbidden|NotFound/.test(name)) return false
  return !/\b(400|401|403|404)\b/.test(String(error))
}

export function mergeTouchedRecord<T>(snapshot: Record<string, T>, current: Record<string, T>, touched: Set<string>) {
  const merged = { ...snapshot }
  for (const id of touched) {
    if (id in current) merged[id] = current[id]
    else delete merged[id]
  }
  return merged
}

export function mergeTouchedSessions<T extends { id: string }>(snapshot: T[], current: T[], touched: Set<string>) {
  const merged = new Map(snapshot.map((session) => [session.id, session]))
  const latest = new Map(current.map((session) => [session.id, session]))
  for (const id of touched) {
    const session = latest.get(id)
    if (session) merged.set(id, session)
    else merged.delete(id)
  }
  return [...merged.values()].sort((a, b) => a.id.localeCompare(b.id))
}
