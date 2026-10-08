import path from "node:path"
import { createStore, reconcile } from "solid-js/store"
import { readJson, writeJsonAtomic } from "../util/persistence"

export type SessionModel = {
  model: { providerID: string; modelID: string }
  variants: Record<string, string>
}

// Serialize replacements of the same file, including across provider remounts.
const writes = new Map<string, Promise<void>>()

export function createSessionModels(directory: string, onError: () => void) {
  const [store, setStore] = createStore<Record<string, { ready: boolean; selection?: SessionModel }>>({})
  const reads = new Map<string, Promise<void>>()
  const file = (id: string) => path.join(directory, "session-model", `session-${encodeURIComponent(id)}.json`)

  function save(id: string, selection: SessionModel) {
    const snapshot = { model: { ...selection.model }, variants: { ...selection.variants } }
    setStore(id, reconcile({ ready: true, selection: snapshot }))
    const filename = file(id)
    const write = (writes.get(filename) ?? Promise.resolve())
      .then(() => writeJsonAtomic(filename, snapshot))
      .catch(onError)
    writes.set(filename, write)
    void write.finally(() => {
      if (writes.get(filename) === write) writes.delete(filename)
    })
    return write
  }

  return {
    ready(id: string) {
      return store[id]?.ready ?? false
    },
    get(id: string) {
      return store[id]?.selection
    },
    load(id: string, override?: SessionModel["model"]) {
      if (store[id]?.ready) return Promise.resolve()
      const pending = reads.get(id)
      if (pending) return pending
      const read = readJson<unknown>(file(id))
        .catch(() => undefined)
        .then((value) => {
          // A choice made while disk I/O is pending must win over the older file.
          if (store[id]?.ready) return undefined
          const selection = parseSessionModel(value)
          if (override) return save(id, { model: override, variants: selection?.variants ?? {} })
          setStore(id, { ready: true, selection })
          return undefined
        })
        .catch(() => {})
        .finally(() => {
          if (!store[id]?.ready) setStore(id, { ready: true })
          reads.delete(id)
        })
      reads.set(id, read)
      return read
    },
    set: save,
  }
}

function parseSessionModel(value: unknown): SessionModel | undefined {
  if (!value || typeof value !== "object" || !("model" in value)) return undefined
  const model = value.model
  if (!model || typeof model !== "object" || !("providerID" in model) || !("modelID" in model)) return undefined
  if (typeof model.providerID !== "string" || typeof model.modelID !== "string") return undefined
  if (!("variants" in value) || !value.variants || typeof value.variants !== "object") return undefined
  return {
    model: { providerID: model.providerID, modelID: model.modelID },
    variants: Object.fromEntries(Object.entries(value.variants).filter((entry) => typeof entry[1] === "string")),
  }
}
