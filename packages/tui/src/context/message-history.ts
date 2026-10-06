import type { Message, Part } from "@opencode-ai/sdk/v2"
import { partForDisplay } from "./part-display"

export const MESSAGE_PAGE_SIZE = 100

// Reconnect refreshes only the window the user has already loaded, in bounded
// pages. A fresh attach still fetches one page rather than the entire transcript.
export async function readMessageWindow<T extends { info: { id: string } }>(
  load: (before?: string) => Promise<{ data: T[]; cursor?: string }>,
  through?: string,
) {
  const data: T[] = []
  const cursors = new Set<string>()
  let before: string | undefined
  while (true) {
    const page = await load(before)
    data.unshift(...page.data)
    if (!page.cursor || !through || page.data.some((item) => item.info.id <= through)) {
      return { data, cursor: page.cursor }
    }
    if (!page.data.length || cursors.has(page.cursor)) throw new Error("Message history cursor did not advance")
    cursors.add(page.cursor)
    before = page.cursor
  }
}

export function mergeMessageHistory(snapshot: Message[], current: Message[], touched: Set<string>, older = false) {
  const merged = new Map((older ? current : snapshot).map((message) => [message.id, message]))
  for (const message of snapshot) {
    if (!touched.has(message.id)) merged.set(message.id, message)
  }
  for (const id of touched) {
    const message = current.find((item) => item.id === id)
    if (message) merged.set(id, message)
    else merged.delete(id)
  }
  return [...merged.values()].sort((a, b) => a.time.created - b.time.created || a.id.localeCompare(b.id))
}

export function mergeHistoryParts(snapshot: Part[], current: Part[], touched: Set<string>) {
  const parts = snapshot.flatMap((part) => {
    const latest = current.find((item) => item.id === part.id)
    if (touched.has(part.id)) return latest ? [latest] : []
    if (
      latest &&
      (part.type === "text" || part.type === "reasoning") &&
      (latest.type === "text" || latest.type === "reasoning") &&
      part.text.length === 0 &&
      latest.text.length > 0
    ) {
      return [latest]
    }
    return [partForDisplay(part)]
  })
  parts.push(...current.filter((part) => touched.has(part.id) && !parts.some((item) => item.id === part.id)))
  return parts
}
