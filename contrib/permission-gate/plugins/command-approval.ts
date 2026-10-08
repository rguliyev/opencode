import type { Hooks, Plugin } from "@opencode-ai/plugin"
import { readdirSync, realpathSync, statSync } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"

// The gate lives in ../lib/gate.ts. This entry point reloads it, with the
// libraries beside it, when an installed file there changes, so a
// protected-config install takes effect on the next request without
// restarting OpenCode. Hooks OpenCode calls only at startup or once per tool
// (config, provider.models, tool.definition) are recorded and replayed into
// each reloaded copy. A reload that fails keeps the copy already running.
const libDir = realpathSync(fileURLToPath(new URL("../lib/", import.meta.url)))
const gateFile = path.join(libDir, "gate.ts")

function libStamp() {
  return readdirSync(libDir)
    .filter((name) => /\.(?:ts|json)$/.test(name) && !name.endsWith(".test.ts"))
    .sort()
    .map((name) => {
      const info = statSync(path.join(libDir, name))
      return `${name}:${info.size}:${info.mtimeMs}`
    })
    .join("|")
}

type AnyHook = (...args: unknown[]) => unknown

const CommandApproval: Plugin = async (input) => {
  const replay: { config?: unknown[]; models?: unknown[]; definitions: Map<string, unknown[]> } = {
    definitions: new Map(),
  }
  let stamp = libStamp()
  let hooks: Hooks = await (await import(gateFile)).default(input)
  let reloading: Promise<void> | undefined

  const reload = async () => {
    const next = libStamp()
    if (next === stamp) return
    try {
      for (const key of Object.keys(require.cache)) if (key.startsWith(libDir + path.sep)) delete require.cache[key]
      const fresh: Hooks = await (await import(gateFile)).default(input)
      const call = (hook: unknown, args: unknown[] | undefined) =>
        typeof hook === "function" && args ? (hook as AnyHook)(...args) : undefined
      await call((fresh as Record<string, unknown>).config, replay.config)
      await call((fresh.provider as Record<string, unknown> | undefined)?.models, replay.models)
      for (const args of replay.definitions.values()) await call((fresh as Record<string, unknown>)["tool.definition"], args)
      hooks = fresh
      stamp = next
    } catch (error) {
      console.error("command-approval: reload failed; keeping the running gate", error)
      stamp = next
    }
  }
  const current = async () => {
    reloading ??= reload().finally(() => (reloading = undefined))
    await reloading
    return hooks as Record<string, unknown>
  }

  const delegate = (name: string) => async (...args: unknown[]) => {
    if (name === "config") replay.config = args
    if (name === "tool.definition") {
      const toolID = (args[0] as { toolID?: string } | undefined)?.toolID ?? ""
      replay.definitions.set(toolID, args)
      if (replay.definitions.size > 200) replay.definitions.delete(replay.definitions.keys().next().value!)
    }
    return ((await current())[name] as AnyHook | undefined)?.(...args)
  }

  const entry: Record<string, unknown> = {}
  for (const [name, value] of Object.entries(hooks)) {
    if (typeof value === "function") entry[name] = delegate(name)
    else if (name === "provider" && value && typeof value === "object")
      entry[name] = {
        ...value,
        models: async (...args: unknown[]) => {
          replay.models = args
          const provider = (await current()).provider as { models?: AnyHook } | undefined
          return provider?.models?.(...args)
        },
      }
    else entry[name] = value
  }
  return entry as Hooks
}

export default CommandApproval
