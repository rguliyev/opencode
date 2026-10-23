import type { Hooks, PluginInput } from "@opencode-ai/plugin"
import type { Session } from "@opencode-ai/sdk"
import { contextBudget, MIN_CONTEXT_BUDGET, withContextBudget } from "../../packages/core/src/session/context-budget"

// Configuration-only defaults. Session/model selections made in the TUI win.
// Requires the fork's per-session context-budget support (cdec78320c or later).
export default async function AgentContextBudget(input: Pick<PluginInput, "client">): Promise<Hooks> {
  const defaults = new Map<string, number | Error>()
  const pending = new Map<string, Promise<void>>()
  return {
    async config(config) {
      defaults.clear()
      for (const [name, agent] of Object.entries(config.agent ?? {})) {
        if (!agent) continue
        const options = agent.options && typeof agent.options === "object" ? agent.options : undefined
        const value: unknown = Object.hasOwn(agent, "context_budget")
          ? agent.context_budget
          : options && Reflect.get(options, "context_budget")
        // Unknown agent fields normalize into model options; never send this one to a provider.
        if (options) Reflect.deleteProperty(options, "context_budget")
        if (agent.disable || agent.mode === "primary" || value === undefined || value === "default") continue
        defaults.set(
          name,
          typeof value === "number" && Number.isSafeInteger(value) && value >= MIN_CONTEXT_BUDGET
            ? value
            : new Error(`Agent ${name}: context_budget must be "default" or an integer >= ${MIN_CONTEXT_BUDGET}`),
        )
      }
    },
    async "chat.params"(_input, output) {
      delete output.options.context_budget
    },
    async "chat.message"(_event, output) {
      // Use the resolved message, not optional/inherited request parameters.
      const { agent, sessionID, model } = output.message
      const budget = defaults.get(agent)
      if (budget === undefined) return
      if (budget instanceof Error) throw budget
      const previous = pending.get(sessionID) ?? Promise.resolve()
      const run = previous
        .catch(() => {})
        .then(async () => {
          // The legacy SDK's types predate metadata; the existing server API supports it.
          const response = await input.client.session.get({ path: { id: sessionID }, throwOnError: true })
          const session: Session & { metadata?: Record<string, unknown> } = response.data
          if (!session.parentID) return
          const metadata = session.metadata ?? {}
          const raw = metadata.agentContextDefaultsApplied
          const applied = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {}
          const key = `${model.providerID}/${model.modelID}`
          if (Object.hasOwn(applied, key)) return
          const body: { title?: string; metadata: Record<string, unknown> } = {
            metadata: {
              ...(contextBudget(metadata, model) === undefined ? withContextBudget(metadata, model, budget) : metadata),
              // Also mark existing manual selections so resetting them isn't undone on the next prompt.
              agentContextDefaultsApplied: { ...applied, [key]: { agent, budget } },
            },
          }
          const updated = await input.client.session.update({ path: { id: sessionID }, body, throwOnError: true })
          const saved: Session & { metadata?: Record<string, unknown> } = updated.data
          if (contextBudget(saved.metadata, model) !== contextBudget(body.metadata, model))
            throw new Error("Server did not persist the subagent context budget")
        })
      pending.set(sessionID, run)
      try {
        await run
      } finally {
        if (pending.get(sessionID) === run) pending.delete(sessionID)
      }
    },
  }
}
