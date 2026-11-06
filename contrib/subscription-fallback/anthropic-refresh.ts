import type { Auth } from "@opencode-ai/sdk"
import type { PluginInput } from "@opencode-ai/plugin"
import path from "node:path"
import { createHash, randomUUID } from "node:crypto"
import { open, readFile, rename, rm } from "node:fs/promises"
import { Global } from "../../packages/core/src/global"
import { Flock } from "../../packages/core/src/util/flock"

type OAuth = Extract<Auth, { type: "oauth" }> & { refreshExpiresAt?: number }
type Notice = { title: string; message: string; variant: "warning"; duration: number }
export type RefreshOptions = {
  getAuth: () => Promise<(Auth & { refreshExpiresAt?: number }) | undefined>
  save: (value: OAuth, expectedRefresh: string) => Promise<boolean>
  notify: (notice: Notice) => Promise<unknown>
  log: (message: string) => Promise<unknown>
  lockDir: string
  transport?: typeof fetch
  ensureReady?: () => void
}

// No guessed deadline: an absent value means unknown, not a fresh 30-day grant.
export function refreshExpiry(seconds: unknown, previous?: number) {
  if (typeof seconds !== "number" || !Number.isFinite(seconds) || seconds < 0) return previous
  const deadline = Date.now() + seconds * 1000
  return Number.isSafeInteger(deadline) ? deadline : previous
}

const notices = new Map<string, number>()
const usable = (auth: Auth) => auth.type === "oauth" && !!auth.access && auth.expires > Date.now() + 30_000

async function warn(options: RefreshOptions, key: string, message: string) {
  const id = `${options.lockDir}:${key}`
  if ((notices.get(id) ?? 0) > Date.now()) return
  notices.set(id, Date.now() + 60 * 60 * 1000)
  await Promise.allSettled([
    options.notify({ title: "Anthropic login", message, variant: "warning", duration: 15_000 }),
    options.log(message),
  ])
}

async function expiryWarning(options: RefreshOptions, auth: OAuth) {
  if (auth.refreshExpiresAt === undefined || auth.refreshExpiresAt - Date.now() > 3 * 86_400_000) return
  await warn(
    options,
    `expiry:${auth.refreshExpiresAt}`,
    `Claude subscription renewal expires ${new Date(auth.refreshExpiresAt).toISOString()}. Reauthenticate with opencode auth login --provider anthropic --method "Claude Pro/Max". No paid credential switch was made.`,
  )
}

export async function freshAnthropicAuth(options: RefreshOptions): Promise<Auth> {
  const initial = await options.getAuth()
  if (!initial) throw new Error("Claude login was removed; authenticate before retrying.")
  if (initial.type !== "oauth") return initial
  await expiryWarning(options, initial)
  if (usable(initial)) return initial
  // Same lock for every project/directory and process using this OpenCode home.
  return Flock.withLock(
    "anthropic-oauth-refresh",
    async () => {
      const auth = await options.getAuth()
      if (!auth) throw new Error("Claude login was removed; authenticate before retrying.")
      if (auth.type !== "oauth") return auth
      if (usable(auth)) return auth
      const journal = path.join(options.lockDir, ".anthropic-oauth-renewal.json")
      const fingerprint = createHash("sha256").update(auth.refresh).digest("hex")
      const previous = await readFile(journal, "utf8").catch((error: NodeJS.ErrnoException) => {
        if (error.code === "ENOENT") return undefined
        throw new Error("Cannot read Claude renewal recovery record; no token exchange attempted.")
      })
      if (previous !== undefined) {
        let record: { fingerprint?: string }
        try {
          record = JSON.parse(previous)
        } catch {
          throw new Error("Invalid Claude renewal recovery record; no token exchange attempted.")
        }
        if (!record || typeof record.fingerprint !== "string")
          throw new Error("Invalid Claude renewal recovery record; no token exchange attempted.")
        if (record.fingerprint === fingerprint) {
          await warn(
            options,
            "unfinished",
            "Claude login needs reauthentication: a previous renewal did not complete safely. The same token will not be exchanged again. No paid credential switch was made.",
          )
          throw new Error("Claude login needs reauthentication; previous renewal outcome is unsafe to retry.")
        }
      }
      if (process.env.OPENCODE_AUTH_CONTENT)
        throw new Error("Cannot safely rotate Claude credentials while OPENCODE_AUTH_CONTENT overrides saved auth.")
      options.ensureReady?.()
      // Write-ahead marker: even a crash or lost response must not let another
      // process reuse a potentially consumed token. It contains only a digest.
      const temporary = `${journal}.${randomUUID()}.tmp`
      const file = await open(temporary, "wx", 0o600)
      try {
        try {
          await file.writeFile(JSON.stringify({ fingerprint, startedAt: new Date().toISOString() }))
          await file.sync()
        } finally {
          await file.close()
        }
        await rename(temporary, journal)
      } finally {
        await rm(temporary, { force: true })
      }
      const directory = await open(options.lockDir, "r")
      try {
        await directory.sync()
      } finally {
        await directory.close()
      }
      await options.log("Claude OAuth refresh started").catch(() => {})
      // Do not blindly retry an ambiguous token exchange: the server may already
      // have rotated the token even when its response was lost.
      const response = await (options.transport ?? fetch)("https://platform.claude.com/v1/oauth/token", {
        method: "POST",
        signal: AbortSignal.timeout(30_000),
        headers: { "Content-Type": "application/json", Accept: "application/json", "User-Agent": "axios/1.13.6" },
        body: JSON.stringify({
          grant_type: "refresh_token",
          refresh_token: auth.refresh,
          client_id: "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
        }),
      }).catch(() => undefined)
      if (!response?.ok) {
        const current = await options.getAuth()
        if (current?.type === "oauth" && usable(current) && current.refresh !== auth.refresh) return current
        const body = (await response?.json().catch(() => undefined)) as { error?: unknown } | undefined
        const invalid = response?.status === 400 && body?.error === "invalid_grant"
        const message = invalid
          ? 'Claude subscription renewal was rejected (invalid_grant). Run opencode auth login --provider anthropic --method "Claude Pro/Max". No paid credential switch was made.'
          : `Claude subscription renewal failed (${response?.status ?? "network/timeout"}); no saved credentials were changed.`
        await warn(options, invalid ? "rejected" : "transport", message)
        throw new Error(message)
      }
      const body = (await response.json().catch(() => undefined)) as Record<string, unknown> | undefined
      if (
        !body ||
        typeof body.access_token !== "string" ||
        !body.access_token ||
        typeof body.refresh_token !== "string" ||
        !body.refresh_token ||
        typeof body.expires_in !== "number" ||
        !Number.isFinite(body.expires_in) ||
        body.expires_in <= 30 ||
        !Number.isSafeInteger(Date.now() + body.expires_in * 1000)
      ) {
        throw new Error("Claude renewal returned invalid credentials; sign in again. No response secrets were logged.")
      }
      const next: OAuth = {
        ...auth,
        access: body.access_token,
        refresh: body.refresh_token,
        expires: Date.now() + body.expires_in * 1000,
        refreshExpiresAt: refreshExpiry(body.refresh_token_expires_in, auth.refreshExpiresAt),
      }
      // Retry persistence of the SAME pair, never repeat the exchange. Conditional
      // writes protect a concurrent login/logout from being overwritten.
      for (let attempt = 0; attempt < 3; attempt++) {
        const saved = await options.save(next, auth.refresh).catch(() => undefined)
        const current = await options.getAuth()
        if (current?.type === "oauth" && usable(current) && (current.refresh !== auth.refresh || saved === true)) {
          await rm(journal, { force: true }).catch(() => {})
          await options
            .log(
              current.refresh === next.refresh && current.access === next.access
                ? "Claude OAuth refresh persisted successfully"
                : "Claude OAuth renewal preserved a newer login",
            )
            .catch(() => {})
          await expiryWarning(options, current)
          return current
        }
        if (saved === false) throw new Error("Claude credentials changed during renewal; retry with the current login.")
        if (attempt < 2) await new Promise((resolve) => setTimeout(resolve, 100 * (attempt + 1)))
      }
      await warn(
        options,
        "save",
        "Claude renewal succeeded but saving credentials failed. Model request stopped; reauthenticate before retrying. No paid credential switch was made.",
      )
      throw new Error("Failed to persist renewed Claude credentials; model request stopped.")
    },
    { dir: options.lockDir, timeoutMs: 90_000 },
  )
}

export function refreshOptions(input: PluginInput, getAuth: RefreshOptions["getAuth"]): RefreshOptions {
  return {
    getAuth,
    lockDir: path.join(Global.Path.state, "locks"),
    ensureReady: () => {
      if (!input.capabilities?.authConditionalWrite)
        throw new Error(
          "Restart OpenCode with the updated binary before renewing Claude login; this running server lacks safe credential writes.",
        )
    },
    save: async (value, expectedRefresh) => {
      const body = { ...value, expectedRefresh }
      const result = await input.client.auth.set({ path: { id: "anthropic" }, body, throwOnError: true })
      if (!result.response.ok || typeof result.data !== "boolean")
        throw new Error("Auth store did not confirm credential persistence")
      return result.data
    },
    notify: (notice) => input.client.tui.showToast({ body: notice }),
    log: (message) => input.client.app.log({ body: { service: "anthropic-auth", level: "info", message } }),
  }
}
