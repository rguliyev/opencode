import type { Hooks, Plugin } from "@opencode-ai/plugin"
import { credentialPath, wrapAuth } from "./plugin"
import { freshAnthropicAuth, refreshOptions } from "./anthropic-refresh"

// The build resolves this to the already installed, pinned 1.8.6 package. There
// is no replacement auth implementation and no new runtime dependency install.
// @ts-expect-error resolved by build.ts from the verified existing plugin cache
import { AnthropicAuthPlugin } from "@ex-machina/opencode-anthropic-auth"

const plugin: Plugin = async (input, options) => {
  const credentials = credentialPath(options)
  const hooks: Hooks = await AnthropicAuthPlugin(input)
  const loader = hooks.auth?.loader
  if (!loader) throw new Error("Missing Anthropic auth loader")
  hooks.auth!.loader = async (getAuth, models) => {
    // Keep upstream's request rewriting and login flow. Supply fresh credentials
    // before each request, so its unsafe loader-local renewal never executes.
    let loading = true
    const refresh = refreshOptions(input, getAuth)
    const result = await loader(async () => (loading ? getAuth() : freshAnthropicAuth(refresh)), models)
    loading = false
    return result
  }
  return wrapAuth(hooks, input, "anthropic", credentials)
}

export default plugin
