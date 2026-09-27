import { expect, test } from "bun:test"
import { reconnectEvents } from "../../src/context/reconnect-events"

const deadline = <T>(task: Promise<T>) =>
  Promise.race([task, new Promise<never>((_, reject) => setTimeout(() => reject(new Error("stream stalled")), 500))])

test("retries a setup exception without abandoning the listener", async () => {
  const abort = new AbortController()
  let connections = 0
  const received: number[] = []

  await deadline(
    reconnectEvents({
      signal: abort.signal,
      retryDelay: 1,
      maxRetryDelay: 1,
      async connect() {
        if (++connections === 1) throw new Error("server unavailable")
        return (async function* () {
          yield 42
        })()
      },
      onEvent(value) {
        received.push(value)
        abort.abort()
      },
    }),
  )

  expect(connections).toBe(2)
  expect(received).toEqual([42])
})

test("aborts a silent half-open stream and reconnects", async () => {
  const abort = new AbortController()
  let connections = 0

  await deadline(
    reconnectEvents({
      signal: abort.signal,
      heartbeatTimeout: 20,
      retryDelay: 1,
      maxRetryDelay: 1,
      async connect(signal) {
        if (++connections === 1)
          return (async function* () {
            await new Promise<void>((resolve) => signal.addEventListener("abort", () => resolve(), { once: true }))
          })()
        return (async function* () {
          yield "reconnected"
        })()
      },
      onEvent(value) {
        expect(value).toBe("reconnected")
        abort.abort()
      },
    }),
  )

  expect(connections).toBe(2)
})

test("heartbeat events keep a healthy idle stream connected", async () => {
  const abort = new AbortController()
  let connections = 0
  let heartbeats = 0

  await deadline(
    reconnectEvents({
      signal: abort.signal,
      heartbeatTimeout: 25,
      retryDelay: 1,
      async connect() {
        connections++
        return (async function* () {
          for (let i = 0; i < 4; i++) {
            await new Promise((resolve) => setTimeout(resolve, 8))
            yield "heartbeat"
          }
        })()
      },
      onEvent() {
        if (++heartbeats === 4) abort.abort()
      },
    }),
  )

  expect(heartbeats).toBe(4)
  expect(connections).toBe(1)
})

test("flushes queued events after a handler throws and retries", async () => {
  const abort = new AbortController()
  let connections = 0
  let flushed = 0

  await deadline(
    reconnectEvents({
      signal: abort.signal,
      retryDelay: 1,
      maxRetryDelay: 1,
      async connect() {
        connections++
        return (async function* () {
          yield connections
        })()
      },
      onEvent(value) {
        if (value === 1) throw new Error("event handler failed")
        abort.abort()
      },
      onAttemptEnd() {
        flushed++
        if (flushed === 1) throw new Error("flush failed")
      },
    }),
  )

  expect(connections).toBe(2)
  expect(flushed).toBe(2)
})
