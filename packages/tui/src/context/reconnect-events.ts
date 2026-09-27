export async function reconnectEvents<T>(input: {
  signal: AbortSignal
  connect: (signal: AbortSignal) => Promise<AsyncIterable<T>>
  onEvent: (event: T) => void
  onAttemptEnd?: () => void
  onError?: (error: unknown) => void
  heartbeatTimeout?: number
  retryDelay?: number
  maxRetryDelay?: number
}) {
  let attempt = 0
  const report = (error: unknown) => {
    try {
      input.onError?.(error)
    } catch {}
  }
  while (!input.signal.aborted) {
    const current = new AbortController()
    const stop = () => current.abort()
    input.signal.addEventListener("abort", stop, { once: true })
    if (input.signal.aborted) stop()
    let watchdog: ReturnType<typeof setTimeout> | undefined
    const watch = () => {
      if (watchdog) clearTimeout(watchdog)
      watchdog = setTimeout(() => {
        report(new Error("event stream heartbeat timed out"))
        stop()
      }, input.heartbeatTimeout ?? 35_000)
    }
    watch()
    try {
      const events = await input.connect(current.signal)
      for await (const event of events) {
        if (current.signal.aborted) break
        watch()
        attempt = 0
        input.onEvent(event)
      }
    } catch (error) {
      // Setup and event handlers may throw even when the SSE client handles
      // transport errors. Neither may permanently stop updates.
      if (!current.signal.aborted && !input.signal.aborted) report(error)
    } finally {
      if (watchdog) clearTimeout(watchdog)
      input.signal.removeEventListener("abort", stop)
      current.abort()
      try {
        input.onAttemptEnd?.()
      } catch {
        // A failed batch listener must not stop a subsequent subscription.
      }
    }

    if (input.signal.aborted) break
    attempt += 1
    const backoff = Math.min((input.retryDelay ?? 1_000) * 2 ** (attempt - 1), input.maxRetryDelay ?? 30_000)
    await new Promise<void>((resolve) => {
      const delay = setTimeout(done, backoff)
      const doneOnAbort = () => {
        clearTimeout(delay)
        done()
      }
      function done() {
        input.signal.removeEventListener("abort", doneOnAbort)
        resolve()
      }
      input.signal.addEventListener("abort", doneOnAbort, { once: true })
      if (input.signal.aborted) doneOnAbort()
    })
  }
}
