import { PermissionV1 } from "@opencode-ai/core/v1/permission"
import { LayerNode } from "@opencode-ai/core/effect/layer-node"
import { describe, expect } from "bun:test"
import path from "path"
import { symlink } from "node:fs/promises"
import { Effect } from "effect"
import { CrossSpawnSpawner } from "@opencode-ai/core/cross-spawn-spawner"
import type { Tool } from "@/tool/tool"
import { assertExternalDirectoryEffect } from "../../src/tool/external-directory"
import { Filesystem } from "@/util/filesystem"
import { TestInstance, tmpdirScoped } from "../fixture/fixture"
import type { Permission } from "../../src/permission"
import { SessionID, MessageID } from "../../src/session/schema"
import { testEffect } from "../lib/effect"

const it = testEffect(LayerNode.compile(CrossSpawnSpawner.node))

const baseCtx: Omit<Tool.Context, "ask"> = {
  sessionID: SessionID.make("ses_test"),
  messageID: MessageID.make("msg_test"),
  callID: "",
  agent: "build",
  abort: AbortSignal.any([]),
  messages: [],
  metadata: () => Effect.void,
}

const glob = (p: string) =>
  process.platform === "win32" ? Filesystem.normalizePathPattern(p) : p.replaceAll("\\", "/")

function makeCtx() {
  const requests: Array<Omit<PermissionV1.Request, "id" | "sessionID" | "tool">> = []
  const ctx: Tool.Context = {
    ...baseCtx,
    ask: (req) =>
      Effect.sync(() => {
        requests.push(req)
      }),
  }
  return { requests, ctx }
}

describe("tool.assertExternalDirectory", () => {
  it.live("no-ops for empty target", () =>
    Effect.gen(function* () {
      const { requests, ctx } = makeCtx()

      yield* assertExternalDirectoryEffect(ctx)

      expect(requests.length).toBe(0)
    }),
  )

  it.instance("no-ops for paths inside the instance directory", () =>
    Effect.gen(function* () {
      const test = yield* TestInstance
      const { requests, ctx } = makeCtx()

      yield* assertExternalDirectoryEffect(ctx, path.join(test.directory, "file.txt"))

      expect(requests.length).toBe(0)
    }),
  )

  it.instance("asks with a single canonical glob", () =>
    Effect.gen(function* () {
      const test = yield* TestInstance
      const { requests, ctx } = makeCtx()

      const target = path.join(path.dirname(test.directory), "outside", "file.txt")
      const expected = glob(path.join(path.dirname(target), "*"))

      yield* assertExternalDirectoryEffect(ctx, target)

      const req = requests.find((r) => r.permission === "external_directory")
      expect(req).toBeDefined()
      expect(req!.patterns).toEqual([expected])
      expect(req!.always).toEqual([expected])
    }),
  )

  it.instance("uses target directory when kind=directory", () =>
    Effect.gen(function* () {
      const test = yield* TestInstance
      const { requests, ctx } = makeCtx()

      const target = path.join(path.dirname(test.directory), "outside")
      const expected = glob(path.join(target, "*"))

      yield* assertExternalDirectoryEffect(ctx, target, { kind: "directory" })

      const req = requests.find((r) => r.permission === "external_directory")
      expect(req).toBeDefined()
      expect(req!.patterns).toEqual([expected])
      expect(req!.always).toEqual([expected])
    }),
  )

  if (process.platform !== "win32") {
    it.instance("asks for a symlink target outside the project", () =>
      Effect.gen(function* () {
        const test = yield* TestInstance
        const outside = yield* tmpdirScoped()
        const link = path.join(test.directory, "outside-link")
        yield* Effect.promise(() => symlink(outside, link, "dir"))
        const { requests, ctx } = makeCtx()

        yield* assertExternalDirectoryEffect(ctx, path.join(link, "file.txt"))

        const req = requests.find((item) => item.permission === "external_directory")
        expect(req).toBeDefined()
        expect(req!.patterns).toEqual([glob(path.join(outside, "*"))])
        expect(req!.metadata).toMatchObject({
          filepath: path.join(link, "file.txt"),
          resolved_filepath: path.join(outside, "file.txt"),
        })
      }),
    )

    it.instance("asks for a dangling symlink pointing to an outside file", () =>
      Effect.gen(function* () {
        const test = yield* TestInstance
        const outside = yield* tmpdirScoped()
        const target = path.join(outside, "not-created.txt")
        const link = path.join(test.directory, "dangling-link")
        yield* Effect.promise(() => symlink(target, link, "file"))
        const { requests, ctx } = makeCtx()

        yield* assertExternalDirectoryEffect(ctx, link)

        const req = requests.find((item) => item.permission === "external_directory")
        expect(req).toBeDefined()
        expect(req!.patterns).toEqual([glob(path.join(outside, "*"))])
        expect(req!.metadata).toMatchObject({ filepath: link, resolved_filepath: target })
      }),
    )

    it.instance("asks for a file under a dangling symlinked outside directory", () =>
      Effect.gen(function* () {
        const test = yield* TestInstance
        const outside = yield* tmpdirScoped()
        const target = path.join(outside, "not-created-dir")
        const link = path.join(test.directory, "dangling-dir-link")
        yield* Effect.promise(() => symlink(target, link, "dir"))
        const { requests, ctx } = makeCtx()

        yield* assertExternalDirectoryEffect(ctx, path.join(link, "new.txt"))

        const req = requests.find((item) => item.permission === "external_directory")
        expect(req).toBeDefined()
        expect(req!.patterns).toEqual([glob(path.join(target, "*"))])
        expect(req!.metadata).toMatchObject({
          filepath: path.join(link, "new.txt"),
          resolved_filepath: path.join(target, "new.txt"),
        })
      }),
    )
  }

  it.live("skips prompting when bypass=true", () =>
    Effect.gen(function* () {
      const { requests, ctx } = makeCtx()

      yield* assertExternalDirectoryEffect(ctx, "/tmp/outside/file.txt", { bypass: true })

      expect(requests.length).toBe(0)
    }),
  )

  if (process.platform === "win32") {
    it.instance(
      "normalizes Windows path variants to one glob",
      () =>
        Effect.gen(function* () {
          const { requests, ctx } = makeCtx()

          const outerTmp = yield* tmpdirScoped()
          yield* Effect.promise(() => Bun.write(path.join(outerTmp, "outside.txt"), "x"))

          const target = path.join(outerTmp, "outside.txt")
          const alt = target
            .replace(/^[A-Za-z]:/, "")
            .replaceAll("\\", "/")
            .toLowerCase()

          yield* assertExternalDirectoryEffect(ctx, alt)

          const req = requests.find((r) => r.permission === "external_directory")
          const expected = glob(path.join(outerTmp, "*"))
          expect(req).toBeDefined()
          expect(req!.patterns).toEqual([expected])
          expect(req!.always).toEqual([expected])
        }),
      { git: true },
    )

    it.instance(
      "uses drive root glob for root files",
      () =>
        Effect.gen(function* () {
          const { requests, ctx } = makeCtx()

          const tmp = yield* TestInstance
          const root = path.parse(tmp.directory).root
          const target = path.join(root, "boot.ini")

          yield* assertExternalDirectoryEffect(ctx, target)

          const req = requests.find((r) => r.permission === "external_directory")
          const expected = path.join(root, "*")
          expect(req).toBeDefined()
          expect(req!.patterns).toEqual([expected])
          expect(req!.always).toEqual([expected])
        }),
      { git: true },
    )
  }
})
