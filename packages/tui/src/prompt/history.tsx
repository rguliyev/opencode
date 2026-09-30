import path from "path"
import { createEffect, onCleanup } from "solid-js"
import { unwrap } from "solid-js/store"
import type { AgentPart, FilePart, TextPart } from "@opencode-ai/sdk/v2"
import { createSimpleContext } from "../context/helper"
import { useRoute } from "../context/route"
import { useSDK } from "../context/sdk"
import { useTuiPaths } from "../context/runtime"
import { readJson, readText, writeJsonAtomic } from "../util/persistence"

export type PromptInfo = {
  input: string
  mode?: "normal" | "shell"
  parts: (
    | Omit<FilePart, "id" | "messageID" | "sessionID">
    | Omit<AgentPart, "id" | "messageID" | "sessionID">
    | (Omit<TextPart, "id" | "messageID" | "sessionID"> & {
        source?: {
          text: {
            start: number
            end: number
            value: string
          }
        }
      })
  )[]
}

export type PromptHistoryEntry = PromptInfo & { sessionID?: string }
export const MAX_HISTORY_ENTRIES = 50

function validEntry(value: unknown): value is PromptHistoryEntry {
  if (!value || typeof value !== "object") return false
  if (!("input" in value) || typeof value.input !== "string") return false
  if (
    !("parts" in value) ||
    !Array.isArray(value.parts) ||
    !value.parts.every((part) => part && typeof part === "object" && "type" in part && typeof part.type === "string")
  )
    return false
  if ("mode" in value && value.mode !== undefined && value.mode !== "normal" && value.mode !== "shell") return false
  if ("sessionID" in value && value.sessionID !== undefined && typeof value.sessionID !== "string") return false
  return true
}

export function retainPromptHistory(entries: PromptHistoryEntry[]) {
  const counts = new Map<string | undefined, number>()
  return entries
    .toReversed()
    .filter((entry) => {
      const count = counts.get(entry.sessionID) ?? 0
      counts.set(entry.sessionID, count + 1)
      return count < MAX_HISTORY_ENTRIES
    })
    .reverse()
}

export function parsePromptHistory(text: string) {
  return retainPromptHistory(
    text
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        try {
          return JSON.parse(line) as unknown
        } catch {
          return undefined
        }
      })
      .filter(validEntry),
  )
}

export function isDuplicateEntry(previous: PromptInfo | undefined, next: PromptInfo): boolean {
  if (!previous) return false
  return JSON.stringify(previous) === JSON.stringify(next)
}

type SessionPromptMessage = {
  info: { role: string }
  parts: { type: string; text?: string; synthetic?: boolean }[]
}

export function promptsFromMessages(messages: SessionPromptMessage[]) {
  return messages
    .flatMap((message): PromptInfo[] => {
      if (message.info.role !== "user") return []
      const input = message.parts
        .filter((part) => part.type === "text" && !part.synthetic && typeof part.text === "string")
        .map((part) => part.text)
        .join("\n")
      if (!input.trim()) return []
      // Old client-local entries retain attachments. The server fallback only
      // restores text, rather than pretending an attachment is still available.
      return [{ input, parts: [] }]
    })
    .slice(-MAX_HISTORY_ENTRIES)
}

export function promptHistoryForSession(
  entries: PromptHistoryEntry[],
  sessionID: string | undefined,
  server: PromptInfo[] = [],
) {
  const local = entries.filter((entry) => entry.sessionID === sessionID)
  if (!sessionID) return local
  const matched = new Set<number>()
  const restored = server.map((entry) => {
    const index = local.findIndex((item, index) => !matched.has(index) && item.input === entry.input)
    if (index === -1) return entry
    matched.add(index)
    return local[index]
  })
  return [...restored, ...local.filter((_, index) => !matched.has(index))].slice(-MAX_HISTORY_ENTRIES)
}

export const { use: usePromptHistory, provider: PromptHistoryProvider } = createSimpleContext({
  name: "PromptHistory",
  init: () => {
    const paths = useTuiPaths()
    const route = useRoute()
    const sdk = useSDK()
    const historyPath = path.join(paths.state, "prompt-history.json")
    let history: PromptHistoryEntry[] = []
    const server = new Map<string, PromptInfo[]>()
    const index = new Map<string | undefined, number>()
    const ready = readJson<unknown>(historyPath)
      .then((value) => (Array.isArray(value) ? retainPromptHistory(value.filter(validEntry)) : []))
      .catch(() => readText(path.join(paths.state, "prompt-history.jsonl")).then(parsePromptHistory).catch(() => []))
      .then((loaded) => {
        history = retainPromptHistory([...loaded, ...history])
      })
    let writing = Promise.resolve()

    createEffect(() => {
      const sessionID = route.data.type === "session" ? route.data.sessionID : undefined
      if (!sessionID || sessionID === "dummy") return
      const controller = new AbortController()
      onCleanup(() => controller.abort())
      void ready
        .then(() => {
          if (controller.signal.aborted || history.filter((entry) => entry.sessionID === sessionID).length >= MAX_HISTORY_ENTRIES)
            return undefined
          return sdk.client.session.messages({ sessionID, limit: 500 }, { signal: controller.signal, throwOnError: true })
        })
        .then((response) => {
          if (controller.signal.aborted || !response) return
          server.set(sessionID, promptsFromMessages(response.data ?? []))
          index.delete(sessionID)
        })
        .catch(() => {})
    })

    return {
      move(direction: 1 | -1, input: string, sessionID?: string) {
        const entries = promptHistoryForSession(history, sessionID, server.get(sessionID ?? ""))
        if (!entries.length) return undefined
        const currentIndex = index.get(sessionID) ?? 0
        const current = entries.at(currentIndex)
        if (current?.input !== input && input.length) return undefined
        const next = currentIndex + direction
        if (Math.abs(next) > entries.length || next > 0) return undefined
        index.set(sessionID, next)
        if (next === 0) return { input: "", parts: [] }
        return entries.at(next)
      },
      append(item: PromptInfo, sessionID?: string) {
        const entry = { ...structuredClone(unwrap(item)), ...(sessionID ? { sessionID } : {}) }
        const previous = history.findLast((value) => value.sessionID === sessionID)
        if (isDuplicateEntry(previous, entry)) {
          index.set(sessionID, 0)
          return
        }
        history = retainPromptHistory([...history, entry])
        index.set(sessionID, 0)
        writing = writing
          .then(() => ready)
          .then(() => writeJsonAtomic(historyPath, history))
          .catch(() => {})
      },
    }
  },
})
