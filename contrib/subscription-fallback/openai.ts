import type { Plugin } from "@opencode-ai/plugin"
import { CodexAuthPlugin } from "../../packages/opencode/src/plugin/openai/codex"
import { credentialPath, wrapAuth } from "./plugin"

const plugin: Plugin = async (input, options) => {
  const credentials = credentialPath(options)
  const hooks = await CodexAuthPlugin(input, { experimentalWebSockets: options?.experimentalWebSockets !== false })
  return wrapAuth(hooks, input, "openai", credentials)
}

export default plugin
