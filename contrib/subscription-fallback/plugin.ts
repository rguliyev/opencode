import type { Hooks, PluginInput } from "@opencode-ai/plugin"
import type { Auth } from "@opencode-ai/sdk"
import { readFile, stat } from "node:fs/promises"
import { isAbsolute } from "node:path"
import { createSubscriptionFallback } from "./fallback"

// Read-only private sidecar. The plugins never migrate, replace, or refresh the
// fallback credential, and never write OpenCode's primary auth store.
export async function readFallback(file: string, provider: "openai" | "anthropic"): Promise<Auth | undefined> {
  if (!isAbsolute(file)) return
  const info = await stat(file).catch(() => undefined)
  if (!info?.isFile() || (info.mode & 0o077) !== 0) return
  const data: unknown = await readFile(file, "utf8")
    .then(JSON.parse)
    .catch(() => undefined)
  if (!data || typeof data !== "object") return
  const value = Reflect.get(data, `${provider}-fallback`)
  if (
    provider === "openai" &&
    value?.type === "oauth" &&
    value.refresh === "" &&
    typeof value.access === "string" &&
    value.access.startsWith("at-") &&
    (value.expires === undefined || value.expires > Date.now())
  )
    return value
  if (provider === "anthropic" && value?.type === "api" && typeof value.key === "string" && value.key.trim())
    return value
}

export function wrapAuth(hooks: Hooks, input: PluginInput, provider: "openai" | "anthropic", credentials: string) {
  const auth = hooks.auth
  const loader = auth?.loader
  if (!auth || !loader || auth.provider !== provider) throw new Error(`Missing ${provider} auth loader`)
  return {
    ...hooks,
    auth: {
      ...auth,
      async loader(getAuth, models) {
        const options = await loader(getAuth, models)
        if (typeof options.fetch !== "function") return options
        return {
          ...options,
          fetch: createSubscriptionFallback({
            provider,
            primary: options.fetch,
            getPrimary: getAuth,
            getFallback: () => readFallback(credentials, provider),
            notify: async (notice) => {
              await Promise.allSettled([
                input.client.tui.showToast({ body: notice }),
                input.client.app.log({
                  body: { service: "subscription-fallback", level: "warn", message: notice.message },
                }),
              ])
            },
          }),
        }
      },
    },
  } satisfies Hooks
}

export function credentialPath(options?: Record<string, unknown>) {
  if (typeof options?.credentials !== "string" || !isAbsolute(options.credentials))
    throw new Error("subscription-fallback requires an absolute private credentials path")
  return options.credentials
}
