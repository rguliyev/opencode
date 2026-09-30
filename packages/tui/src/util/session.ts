export function isDefaultTitle(title: string) {
  return /^(New session - |Child session - )\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(title)
}

export function latestQueuedPrompt<
  T extends { id: string; role: "user" | "assistant"; time: { created: number; completed?: number } },
>(messages: readonly T[]) {
  const assistant = messages.findLastIndex((message) => message.role === "assistant")
  if (assistant === -1 || messages[assistant]?.time.completed) return undefined
  return messages.findLast((message, index) => index > assistant && message.role === "user")
}
