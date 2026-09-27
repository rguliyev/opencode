/** @jsxImportSource @opentui/solid */
import { expect, test } from "bun:test"
import { createDefaultOpenTuiKeymap } from "@opentui/keymap/opentui"
import { testRender, useRenderer } from "@opentui/solid"
import type { PermissionRequest } from "@opencode-ai/sdk/v2"
import { onCleanup } from "solid-js"
import { mkdir } from "node:fs/promises"
import path from "node:path"
import { tmpdir } from "../../fixture/fixture"
import { eventSource, json } from "../../fixture/tui-sdk"
import { TestTuiContexts } from "../../fixture/tui-environment"
import { createTuiResolvedConfig } from "../../fixture/tui-runtime"
import { TuiConfigProvider } from "../../../src/config"
import { KVProvider } from "../../../src/context/kv"
import { LocationProvider } from "../../../src/context/location"
import { ProjectProvider } from "../../../src/context/project"
import { SDKProvider } from "../../../src/context/sdk"
import { SyncContext, useSync } from "../../../src/context/sync"
import { ThemeProvider } from "../../../src/context/theme"
import { OpencodeKeymapProvider, registerOpencodeKeymap } from "../../../src/keymap"
import { PermissionPrompt } from "../../../src/routes/session/permission"

async function waitFor(app: Awaited<ReturnType<typeof testRender>>, text: string) {
  for (let attempt = 0; attempt < 50; attempt++) {
    await app.renderOnce()
    if (app.captureCharFrame().includes(text)) return
    await Bun.sleep(10)
  }
  throw new Error(`did not render ${text}: ${app.captureCharFrame().trim()}`)
}

async function waitForReply(app: Awaited<ReturnType<typeof testRender>>, replies: unknown[]) {
  for (let attempt = 0; attempt < 50; attempt++) {
    await app.renderOnce()
    if (replies.length) return
    await Bun.sleep(10)
  }
  throw new Error("permission reply was not sent")
}

const request = (reviewed: boolean, child: boolean, commands = 1, total = commands, offset = 0, executed = total) =>
  ({
    id: "per_test",
    sessionID: child ? "ses_child" : "ses_parent",
    permission: "bash",
    patterns: Array.from({ length: total }, (_, index) => `echo test ${index}`),
    always: ["echo *"],
    metadata: reviewed
      ? {
          commandCount: executed,
          reviewItems: Array.from({ length: commands }, (_, position) => {
            const index = offset + position
            return {
              index,
              digest: String.fromCharCode(97 + index).repeat(64),
              command: `echo test ${index}`,
              reason: "Review the command",
            }
          }),
        }
      : { commandCount: executed },
  }) as PermissionRequest

async function mount(
  reviewed: boolean,
  child = false,
  width = 110,
  commands = 1,
  total = commands,
  offset = 0,
  executed = total,
) {
  const tmp = await tmpdir()
  const state = path.join(tmp.path, "state")
  await mkdir(state, { recursive: true })
  await Bun.write(path.join(state, "kv.json"), "{}")
  const replies: unknown[] = []
  const config = createTuiResolvedConfig()
  const fetch = (async (input: RequestInfo | URL) => {
    const value = input instanceof Request ? input : new Request(input)
    if (new URL(value.url).pathname === "/permission/per_test/reply") {
      replies.push(await value.json())
      return json(true)
    }
    throw new Error(`unexpected request: ${value.url}`)
  }) as typeof globalThis.fetch

  function Harness() {
    const renderer = useRenderer()
    const keymap = createDefaultOpenTuiKeymap(renderer)
    const off = registerOpencodeKeymap(keymap, renderer, config)
    onCleanup(off)

    return (
      <TestTuiContexts directory={tmp.path} paths={{ home: tmp.path, state, worktree: tmp.path }}>
        <OpencodeKeymapProvider keymap={keymap}>
          <TuiConfigProvider config={config}>
            <KVProvider>
              <ThemeProvider mode="dark" source={{ discover: async () => ({}) }}>
                <SDKProvider url="http://test" events={eventSource()} fetch={fetch}>
                  <ProjectProvider>
                    <SyncContext.Provider value={{ data: { part: {} } } as ReturnType<typeof useSync>}>
                      <LocationProvider>
                        <PermissionPrompt request={request(reviewed, child, commands, total, offset, executed)} />
                      </LocationProvider>
                    </SyncContext.Provider>
                  </ProjectProvider>
                </SDKProvider>
              </ThemeProvider>
            </KVProvider>
          </TuiConfigProvider>
        </OpencodeKeymapProvider>
      </TestTuiContexts>
    )
  }

  const app = await testRender(() => <Harness />, { width, height: 25, kittyKeyboard: true })
  return {
    app,
    replies,
    async cleanup() {
      app.renderer.destroy()
      await Bun.sleep(25)
      await tmp[Symbol.asyncDispose]()
    },
  }
}

for (const reviewed of [false, true]) {
  for (const child of [false, true]) {
    test(`${reviewed ? "reviewed" : "ordinary"} ${child ? "child" : "parent"} permission offers Do differently without immediate rejection`, async () => {
      const setup = await mount(reviewed, child)
      try {
        await waitFor(setup.app, "Do differently")
        for (let i = 0; i < (reviewed ? 2 : 3); i++) {
          setup.app.mockInput.pressArrow("right")
          await setup.app.renderOnce()
        }
        setup.app.mockInput.pressEnter()
        await waitFor(setup.app, "Tell OpenCode what to do instead")
        expect(setup.app.captureCharFrame()).toContain("A message is required")
        expect(setup.replies).toEqual([])

        setup.app.mockInput.pressEnter()
        await setup.app.renderOnce()
        expect(setup.replies).toEqual([])

        "Use the local tool".split("").forEach((key) => setup.app.mockInput.pressKey(key))
        await setup.app.renderOnce()
        setup.app.mockInput.pressEnter()
        await waitForReply(setup.app, setup.replies)
        expect(setup.replies).toEqual([expect.objectContaining({ reply: "reject", message: "Use the local tool" })])
      } finally {
        await setup.cleanup()
      }
    })
  }
}

test("Do differently stays visible in an 80-column terminal", async () => {
  const setup = await mount(true, false, 80)
  try {
    await waitFor(setup.app, "Do differently")
  } finally {
    await setup.cleanup()
  }
})

test("Allow all approves every flagged command for this call once", async () => {
  const setup = await mount(true, false, 110, 2)
  try {
    await waitFor(setup.app, "Allow all")
    setup.app.mockInput.pressArrow("right")
    await setup.app.renderOnce()
    setup.app.mockInput.pressEnter()
    await waitForReply(setup.app, setup.replies)
    expect(setup.replies).toEqual([
      expect.objectContaining({
        reply: "once",
        commandFeedback: [
          { index: 0, digest: "a".repeat(64), decision: "allow" },
          { index: 1, digest: "b".repeat(64), decision: "allow" },
        ],
      }),
    ])
  } finally {
    await setup.cleanup()
  }
})

test("Allow all approves a multi-command call when only one command is flagged", async () => {
  const setup = await mount(true, false, 110, 1, 2, 1)
  try {
    await waitFor(setup.app, "Allow all")
    setup.app.mockInput.pressArrow("right")
    await setup.app.renderOnce()
    setup.app.mockInput.pressEnter()
    await waitForReply(setup.app, setup.replies)
    expect(setup.replies).toEqual([
      expect.objectContaining({
        reply: "once",
        commandFeedback: [{ index: 1, digest: "b".repeat(64), decision: "allow" }],
      }),
    ])
  } finally {
    await setup.cleanup()
  }
})

test("Allow all approves an ordinary multi-command request once", async () => {
  const setup = await mount(false, false, 110, 1, 2)
  try {
    await waitFor(setup.app, "Allow all")
    expect(setup.app.captureCharFrame()).not.toContain("Allow once")
    setup.app.mockInput.pressEnter()
    await waitForReply(setup.app, setup.replies)
    expect(setup.replies).toEqual([expect.objectContaining({ reply: "once" })])
    expect(setup.replies[0]).not.toHaveProperty("commandFeedback")
  } finally {
    await setup.cleanup()
  }
})

test("Allow all appears when repeated shell commands share one permission pattern", async () => {
  const setup = await mount(true, false, 110, 1, 1, 0, 2)
  try {
    await waitFor(setup.app, "Allow all")
    setup.app.mockInput.pressArrow("right")
    await setup.app.renderOnce()
    setup.app.mockInput.pressEnter()
    await waitForReply(setup.app, setup.replies)
    expect(setup.replies).toEqual([
      expect.objectContaining({
        reply: "once",
        commandFeedback: [{ index: 0, digest: "a".repeat(64), decision: "allow" }],
      }),
    ])
  } finally {
    await setup.cleanup()
  }
})

test("Allow all remains available after approving the first command", async () => {
  const setup = await mount(true, false, 110, 2)
  try {
    await waitFor(setup.app, "Allow all")
    setup.app.mockInput.pressEnter()
    await waitFor(setup.app, "Review flagged command 2 of 2")
    expect(setup.replies).toEqual([])
    setup.app.mockInput.pressArrow("right")
    await setup.app.renderOnce()
    setup.app.mockInput.pressEnter()
    await waitForReply(setup.app, setup.replies)
    expect(setup.replies).toEqual([
      expect.objectContaining({
        reply: "once",
        commandFeedback: [
          { index: 0, digest: "a".repeat(64), decision: "allow" },
          { index: 1, digest: "b".repeat(64), decision: "allow" },
        ],
      }),
    ])
  } finally {
    await setup.cleanup()
  }
})

test("single-command review does not offer Allow all", async () => {
  const setup = await mount(true)
  try {
    await waitFor(setup.app, "Allow this command")
    expect(setup.app.captureCharFrame()).not.toContain("Allow all")
  } finally {
    await setup.cleanup()
  }
})

test("Reject still rejects immediately without an instruction", async () => {
  const setup = await mount(false)
  try {
    await waitFor(setup.app, "Do differently")
    setup.app.mockInput.pressArrow("right")
    await setup.app.renderOnce()
    setup.app.mockInput.pressArrow("right")
    await setup.app.renderOnce()
    setup.app.mockInput.pressEnter()
    await waitForReply(setup.app, setup.replies)
    expect(setup.replies).toEqual([expect.objectContaining({ reply: "reject" })])
    expect(setup.replies[0]).not.toHaveProperty("message")
  } finally {
    await setup.cleanup()
  }
})
