import type { Auth } from "@opencode-ai/sdk"

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

type Fetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
type Provider = "openai" | "anthropic"
type Notice = { title: string; message: string; variant: "warning" | "success"; duration: number }

// Separate auth entries opt in to paid usage. Never replace the subscription credential.
export function createSubscriptionFallback(options: {
  provider: Provider
  primary: Fetch
  getPrimary: () => Promise<Auth | undefined>
  getFallback: () => Promise<Auth | undefined>
  notify: (notice: Notice) => Promise<void>
  transport?: Fetch
  now?: () => number
}) {
  const now = options.now ?? Date.now
  const transport = options.transport ?? fetch
  const limits = new Map<string, { retry: number; reset?: number }>()
  const notices = new Map<string, number>()
  let identity = ""

  async function notify(key: string, message: string, recovered = false) {
    if (notices.size > 1024) {
      for (const [key, expiry] of notices) if (expiry <= now()) notices.delete(key)
    }
    if ((notices.get(key) ?? 0) > now()) return
    notices.set(key, now() + 300_000)
    await options
      .notify({
        title: `${options.provider}: ${recovered ? "subscription restored" : "usage warning"}`,
        message,
        variant: recovered ? "success" : "warning",
        duration: 30_000,
      })
      .catch(() => {})
  }

  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    // SDK requests have replayable JSON bodies. Do not retry streams, Request bodies,
    // arbitrary endpoints, or responses that have already begun streaming to the user.
    const url = new URL(input instanceof Request ? input.url : input.toString())
    const origin = options.provider === "openai" ? "https://api.openai.com" : "https://api.anthropic.com"
    const endpoint = options.provider === "openai" ? "/v1/responses" : "/v1/messages"
    if (
      input instanceof Request ||
      url.origin !== origin ||
      url.pathname !== endpoint ||
      init?.method !== "POST" ||
      typeof init.body !== "string"
    )
      return options.primary(input, init)
    const requestBody = init.body
    const body: unknown = await Promise.resolve()
      .then(() => JSON.parse(requestBody))
      .catch(() => undefined)
    if (!isRecord(body) || typeof body.model !== "string") return options.primary(input, init)
    const primary = await options.getPrimary()
    if (primary?.type !== "oauth" || !primary.refresh) return options.primary(input, init)
    const current = `${Reflect.get(primary, "accountId") ?? ""}:${primary.refresh}`
    if (identity !== current) {
      limits.clear()
      notices.clear()
      identity = current
    }
    const model = body.model
    const headers = new Headers(init.headers)
    const session = headers.get("x-session-affinity") ?? headers.get("session-id") ?? ""
    const key = `${model}:${session}`
    const fallback = await options.getFallback()
    const credential = fallbackCredential(options.provider, fallback)
    const limited = limits.get(model)
    init.signal?.throwIfAborted()

    async function paid(reset?: number) {
      init?.signal?.throwIfAborted()
      await notify(
        `paid:${key}`,
        `${model}: subscription allowance exhausted; switching to PAID fallback. ` +
          (reset ? `Provider reset: ${new Date(reset).toISOString()}. ` : "") +
          "Check/reset limits in the provider dashboard if needed. Subscription is retried within 60 seconds.",
      )
      const paidHeaders = new Headers(headers)
      for (const name of [
        "authorization",
        "x-api-key",
        "chatgpt-account-id",
        "x-openai-internal-codex-residency",
        "x-opencode-title",
      ])
        paidHeaders.delete(name)
      if (options.provider === "openai") paidHeaders.set("authorization", `Bearer ${credential}`)
      if (options.provider === "anthropic") {
        paidHeaders.set("x-api-key", credential!)
        const beta = paidHeaders
          .get("anthropic-beta")
          ?.split(",")
          .filter((x) => !x.trim().startsWith("oauth-"))
        if (beta?.length) paidHeaders.set("anthropic-beta", beta.join(","))
        else paidHeaders.delete("anthropic-beta")
      }
      // PATs use Codex, not the platform API. Never inherit the subscription's workspace ID.
      const target = options.provider === "openai" ? "https://chatgpt.com/backend-api/codex/responses" : url
      const response = await transport(target, { ...init, headers: paidHeaders, redirect: "error" }).catch(
        async (error) => {
          if (!init?.signal?.aborted)
            await notify(
              `failed:${key}`,
              `${model}: paid fallback request failed. Check provider connectivity and limits; no other credential will be tried.`,
            )
          throw error
        },
      )
      if (!response.ok)
        await notify(
          `failed:${key}`,
          `${model}: paid fallback failed (HTTP ${response.status}). Check credentials and reset/increase paid limits if appropriate; no other credential will be tried.`,
        )
      return response
    }

    if (credential && limited && limited.retry > now()) return paid(limited.reset)
    // Plugins may mutate init.headers. Keep the original SDK request for the paid retry.
    const response = await options.primary(input, { ...init, headers: new Headers(headers) })
    const limit = await subscriptionLimit(options.provider, response)
    if (!limit) {
      if (response.ok && limited) {
        limits.delete(model)
        notices.delete(`paid:${key}`)
        await notify(
          `restored:${key}`,
          `${model}: subscription allowance is available again; paid fallback stopped.`,
          true,
        )
      }
      if (response.ok && nearLimit(options.provider, response.headers))
        await notify(
          `near:${key}`,
          `${model}: subscription usage is at least 90%. Check/reset limits if needed. ${credential ? "Paid fallback is configured and may incur charges when the allowance is exhausted." : "No paid fallback credential is configured."}`,
        )
      return response
    }
    const retry = Math.min(now() + 60_000, limit.reset && limit.reset > now() ? limit.reset : Infinity)
    limits.set(model, { retry, reset: limit.reset })
    if (!credential) {
      await notify(
        `missing:${key}`,
        `${model}: subscription allowance exhausted. No valid ${options.provider}-fallback credential is configured; paid usage was NOT started. Check/reset your subscription limits.`,
      )
      return response
    }
    init.signal?.throwIfAborted()
    await response.body?.cancel()
    return paid(limit.reset)
  }
}

function fallbackCredential(provider: Provider, auth?: Auth) {
  if (provider === "anthropic" && auth?.type === "api" && auth.key.trim()) return auth.key
  if (provider === "openai" && auth?.type === "oauth" && !auth.refresh && auth.access.startsWith("at-"))
    return auth.access
  return undefined
}

async function subscriptionLimit(provider: Provider, response: Response): Promise<{ reset?: number } | undefined> {
  if (response.status !== 429) return
  const body: unknown = await response
    .clone()
    .json()
    .catch(() => undefined)
  if (!isRecord(body) || !isRecord(body.error)) return
  const error = body.error
  if (provider === "openai" && (error.type === "usage_limit_reached" || error.code === "usage_limit_reached")) {
    return {
      reset: resetTime(error.resets_at),
    }
  }
  // Generic 429s can be RPM/TPM throttling: require an explicit subscription-window rejection.
  if (provider !== "anthropic" || error.type !== "rate_limit_error") return
  const resets = ["5h", "7d", "7d-sonnet", "7d-opus", "7d_oi"].flatMap((window) => {
    if (response.headers.get(`anthropic-ratelimit-unified-${window}-status`) !== "rejected") return []
    return [resetTime(response.headers.get(`anthropic-ratelimit-unified-${window}-reset`)) ?? 0]
  })
  if (!resets.length && response.headers.get("anthropic-ratelimit-unified-status") === "rejected") {
    return { reset: resetTime(response.headers.get("anthropic-ratelimit-unified-reset")) }
  }
  if (!resets.length) return
  return { reset: Math.max(...resets) || undefined }
}

function resetTime(value: unknown) {
  const ms = (typeof value === "number" || typeof value === "string" ? Number(value) : 0) * 1000
  return Number.isFinite(ms) && ms > 0 && ms <= 8.64e15 ? ms : undefined
}

function nearLimit(provider: Provider, headers: Headers) {
  const names =
    provider === "openai"
      ? ["x-codex-primary-used-percent", "x-codex-secondary-used-percent"]
      : ["anthropic-ratelimit-unified-5h-utilization", "anthropic-ratelimit-unified-7d-utilization"]
  return names.some((name) => {
    const value = Number(headers.get(name))
    return Number.isFinite(value) && value >= (provider === "openai" ? 90 : 0.9)
  })
}
