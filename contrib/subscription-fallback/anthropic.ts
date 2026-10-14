import type { Plugin } from "@opencode-ai/plugin"
import { credentialPath, wrapAuth } from "./plugin"

// The build resolves this to the already installed, pinned 1.8.6 package. There
// is no replacement auth implementation and no new runtime dependency install.
// @ts-expect-error resolved by build.ts from the verified existing plugin cache
import { AnthropicAuthPlugin } from "@ex-machina/opencode-anthropic-auth"

const plugin: Plugin = async (input, options) => {
  const credentials = credentialPath(options)
  const hooks = await AnthropicAuthPlugin(input)
  return wrapAuth(hooks, input, "anthropic", credentials)
}

export default plugin
