import type { Config } from "@/config/config"
import { ConfigV1 } from "@opencode-ai/core/v1/config/config"
import { SessionV1 } from "@opencode-ai/core/v1/session"
import type { Provider } from "@/provider/provider"
import { usableContext } from "@opencode-ai/core/session/context-budget"
import type { MessageV2 } from "./message-v2"

export function usable(input: { cfg: ConfigV1.Info; model: Provider.Model; outputTokenMax?: number; budget?: number }) {
  return usableContext({
    limit: input.model.limit,
    reserved: input.cfg.compaction?.reserved,
    outputTokenMax: input.outputTokenMax,
    budget: input.budget,
  })
}

export function isOverflow(input: {
  cfg: ConfigV1.Info
  tokens: SessionV1.Assistant["tokens"]
  model: Provider.Model
  outputTokenMax?: number
  budget?: number
}) {
  if (input.cfg.compaction?.auto === false) return false
  if (input.model.limit.context === 0) return false

  const count =
    input.tokens.total || input.tokens.input + input.tokens.output + input.tokens.cache.read + input.tokens.cache.write
  return count >= usable(input)
}
