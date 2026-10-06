import { createSignal, onCleanup, onMount } from "solid-js"
import { useSync } from "./sync"
import { errorMessage } from "../util/error"

// Timeline dialogs explicitly request the complete prompt list. Load bounded
// pages without blocking input, and stop fetching when the dialog closes.
export function useFullHistory(sessionID: string) {
  const sync = useSync()
  const [loading, setLoading] = createSignal(true)
  const [error, setError] = createSignal<string>()
  const lifetime = new AbortController()
  onCleanup(() => lifetime.abort())
  onMount(() => {
    void (async () => {
      try {
        await sync.session.sync(sessionID)
        while (!lifetime.signal.aborted && sync.data.history[sessionID]?.cursor) {
          await sync.session.older(sessionID)
        }
      } catch (cause) {
        if (!lifetime.signal.aborted) setError(errorMessage(cause))
      } finally {
        if (!lifetime.signal.aborted) setLoading(false)
      }
    })()
  })
  return { loading, error }
}
