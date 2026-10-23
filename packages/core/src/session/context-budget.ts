// A session/model-specific compaction budget, not a larger provider context window.
export const MIN_CONTEXT_BUDGET = 32_000

type Model = { providerID: string; modelID: string }
type Metadata = Record<string, unknown> | undefined

export function contextBudgets(metadata: Metadata): Record<string, number> {
  const value = metadata?.contextBudgets
  if (!value || typeof value !== "object" || Array.isArray(value)) return {}
  return Object.fromEntries(
    Object.entries(value).filter(
      (entry): entry is [string, number] =>
        typeof entry[1] === "number" && Number.isSafeInteger(entry[1]) && entry[1] >= MIN_CONTEXT_BUDGET,
    ),
  )
}

export function contextBudget(metadata: Metadata, model: Model) {
  return contextBudgets(metadata)[`${model.providerID}/${model.modelID}`]
}

export function withContextBudget(
  metadata: Metadata,
  model: Model,
  value?: number,
): Record<string, unknown> & { contextBudgets: Record<string, number> } {
  if (value !== undefined && (!Number.isSafeInteger(value) || value < MIN_CONTEXT_BUDGET))
    throw new Error(`Context budget must be at least ${MIN_CONTEXT_BUDGET} tokens`)
  const budgets = contextBudgets(metadata)
  const key = `${model.providerID}/${model.modelID}`
  if (value === undefined) delete budgets[key]
  else budgets[key] = value
  return { ...metadata, contextBudgets: budgets }
}

export function usableContext(input: {
  limit: { context: number; input?: number; output: number }
  reserved?: number
  outputTokenMax?: number
  budget?: number
}) {
  if (input.limit.context === 0) return 0
  const output = Math.min(input.limit.output, input.outputTokenMax ?? 32_000) || (input.outputTokenMax ?? 32_000)
  const reserved = input.reserved ?? Math.min(20_000, output)
  const maximum = input.limit.input
    ? Math.max(0, input.limit.input - reserved)
    : Math.max(0, input.limit.context - output)
  return input.budget !== undefined && Number.isSafeInteger(input.budget) && input.budget >= MIN_CONTEXT_BUDGET
    ? Math.min(maximum, input.budget)
    : maximum
}

export function parseContextBudget(text: string) {
  const match = /^(\d+(?:\.\d+)?)\s*([km]?)$/i.exec(text.trim())
  if (!match) return undefined
  const value = Number(match[1]) * (match[2].toLowerCase() === "m" ? 1_000_000 : match[2] ? 1_000 : 1)
  return Number.isSafeInteger(value) && value >= MIN_CONTEXT_BUDGET ? value : undefined
}
