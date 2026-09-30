import path from "path"
import { lstat, readlink, realpath } from "node:fs/promises"
import { Effect } from "effect"
import { InstanceState } from "@/effect/instance-state"
import type * as Tool from "./tool"
import { containsPath } from "../project/instance-context"
import { FSUtil } from "@opencode-ai/core/fs-util"

type Kind = "file" | "directory"

type Options = {
  bypass?: boolean
  kind?: Kind
}

async function canonicalPath(input: string): Promise<string | undefined> {
  let current = path.resolve(input)
  const missing: string[] = []
  // Resolve missing suffixes without losing a dangling symlink's destination.
  // A plain realpath/parent walk would wrongly treat such a link as an in-tree file.
  for (let hop = 0; hop < 128; hop++) {
    try {
      return path.join(await realpath(current), ...missing.reverse())
    } catch (error) {
      if (!(error instanceof Error) || !("code" in error) || !["ENOENT", "ENOTDIR"].includes(String(error.code)))
        return undefined
      try {
        const stat = await lstat(current)
        if (stat.isSymbolicLink()) {
          const target = await readlink(current)
          current = path.join(path.resolve(path.dirname(current), target), ...missing.reverse())
          missing.length = 0
          continue
        }
        // A non-directory component cannot be traversed safely.
        return undefined
      } catch (statError) {
        if (
          !(statError instanceof Error) ||
          !("code" in statError) ||
          !["ENOENT", "ENOTDIR"].includes(String(statError.code))
        )
          return undefined
      }
      const parent = path.dirname(current)
      if (parent === current) return undefined
      missing.push(path.basename(current))
      current = parent
    }
  }
  return undefined
}

export const assertExternalDirectoryEffect = Effect.fn("Tool.assertExternalDirectory")(function* (
  ctx: Tool.Context,
  target?: string,
  options?: Options,
) {
  if (!target) return false

  if (options?.bypass) return false

  const ins = yield* InstanceState.context
  const full = process.platform === "win32" ? FSUtil.normalizePath(target) : target
  const [resolved, projectDir, worktree] = yield* Effect.promise(() =>
    Promise.all([
      canonicalPath(full),
      canonicalPath(ins.directory),
      ins.worktree === "/" ? Promise.resolve("/") : canonicalPath(ins.worktree),
    ]),
  )
  if (!resolved || !projectDir || !worktree)
    return yield* Effect.die(new Error("Cannot resolve external-directory path safely"))
  if (containsPath(resolved, { ...ins, directory: projectDir, worktree })) return false

  const kind = options?.kind ?? "file"
  const effective = resolved
  const dir = kind === "directory" ? effective : path.dirname(effective)
  const glob =
    process.platform === "win32"
      ? FSUtil.normalizePathPattern(path.join(dir, "*"))
      : path.join(dir, "*").replaceAll("\\", "/")

  yield* ctx.ask({
    permission: "external_directory",
    patterns: [glob],
    always: [glob],
    metadata: {
      filepath: full,
      resolved_filepath: resolved,
      parentDir: dir,
    },
  })
  return true
})

export async function assertExternalDirectory(ctx: Tool.Context, target?: string, options?: Options) {
  return Effect.runPromise(assertExternalDirectoryEffect(ctx, target, options))
}
