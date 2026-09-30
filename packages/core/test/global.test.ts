import { describe, expect, test } from "bun:test"
import fs from "fs/promises"
import os from "os"
import path from "path"
import { Global, resolveRuntimePaths } from "@opencode-ai/core/global"

describe("global paths", () => {
  test("tmp path is under the system temp directory", () => {
    expect(Global.Path.tmp).toBe(path.join(os.tmpdir(), "opencode"))
    expect(Global.make().tmp).toBe(Global.Path.tmp)
  })

  test("tmp path is created on module load", async () => {
    expect((await fs.stat(Global.Path.tmp)).isDirectory()).toBe(true)
  })

  test("keeps runtime and configuration separate with OPENCODE_HOME", () => {
    const runtime = path.join(os.tmpdir(), "opencode-runtime")
    expect(resolveRuntimePaths(runtime)).toEqual({
      data: path.join(runtime, "data"),
      cache: path.join(runtime, "cache"),
      config: path.join(os.homedir(), ".opencode"),
      state: path.join(runtime, "state"),
    })
    expect(() => resolveRuntimePaths("relative/path")).toThrow("OPENCODE_HOME must be an absolute path")
  })
})
