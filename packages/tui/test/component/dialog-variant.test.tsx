/** @jsxImportSource @opentui/solid */
import { expect, test } from "bun:test"
import { createDefaultOpenTuiKeymap } from "@opentui/keymap/opentui"
import { testRender, useRenderer } from "@opentui/solid"
import { onCleanup, Show } from "solid-js"
import path from "node:path"
import { tmpdir } from "../fixture/fixture"
import { TestTuiContexts } from "../fixture/tui-environment"
import { createTuiResolvedConfig } from "../fixture/tui-runtime"
import { eventSource, createFetch } from "../fixture/tui-sdk"
import { ModelVariantControl } from "../../src/component/dialog-variant"
import { TuiConfigProvider } from "../../src/config"
import { ArgsProvider } from "../../src/context/args"
import { KVProvider } from "../../src/context/kv"
import { LocalProvider, useLocal } from "../../src/context/local"
import { PermissionProvider } from "../../src/context/permission"
import { RouteProvider, useRoute } from "../../src/context/route"
import { SDKProvider } from "../../src/context/sdk"
import { SyncContext, useSync } from "../../src/context/sync"
import { ThemeProvider, useTheme } from "../../src/context/theme"
import { OpencodeKeymapProvider, registerOpencodeKeymap } from "../../src/keymap"
import { DialogProvider, useDialog } from "../../src/ui/dialog"
import { ToastProvider } from "../../src/ui/toast"

async function mount(options?: { directory?: string; sessionID?: string; model?: string }) {
  const tmp = await tmpdir()
  const directory = options?.directory ?? tmp.path
  const config = createTuiResolvedConfig()
  await Bun.write(path.join(directory, "kv.json"), "{}")
  let local!: ReturnType<typeof useLocal>
  let route!: ReturnType<typeof useRoute>
  let dialog!: ReturnType<typeof useDialog>
  const calls = createFetch()
  // This fixture supplies only the synchronized data consumed by LocalProvider.
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion
  const sync = {
    data: {
      agent: [{ name: "build", mode: "primary", model: { providerID: "test", modelID: "reasoner" } }],
      config: {},
      provider_default: {},
      session: [],
      provider: [
        {
          id: "test",
          name: "Test",
          models: {
            reasoner: { name: "Reasoner", capabilities: { reasoning: true }, variants: { low: {}, high: {} } },
            plain: { name: "Plain", capabilities: { reasoning: false }, variants: { fast: {} } },
            fixed: { name: "Fixed", capabilities: { reasoning: false } },
          },
        },
      ],
    },
  } as unknown as ReturnType<typeof useSync>

  function Control() {
    local = useLocal()
    route = useRoute()
    dialog = useDialog()
    const { theme } = useTheme()
    return (
      <Show when={local.model.variant.list().length > 0}>
        <ModelVariantControl color={theme.warning} />
      </Show>
    )
  }

  function Harness() {
    const renderer = useRenderer()
    const keymap = createDefaultOpenTuiKeymap(renderer)
    const off = registerOpencodeKeymap(keymap, renderer, config)
    onCleanup(off)
    return (
      <TestTuiContexts directory={directory} paths={{ home: directory, state: directory, worktree: directory }}>
        <OpencodeKeymapProvider keymap={keymap}>
          <TuiConfigProvider config={config}>
            <ArgsProvider model={options?.model}>
              <KVProvider>
                <ToastProvider>
                  <RouteProvider
                    initialRoute={options?.sessionID ? { type: "session", sessionID: options.sessionID } : undefined}
                  >
                    <SDKProvider url="http://test" events={eventSource()} fetch={calls.fetch}>
                      <PermissionProvider>
                        <SyncContext.Provider value={sync}>
                          <ThemeProvider mode="dark" source={{ discover: async () => ({}) }}>
                            <LocalProvider>
                              <DialogProvider>
                                <Control />
                              </DialogProvider>
                            </LocalProvider>
                          </ThemeProvider>
                        </SyncContext.Provider>
                      </PermissionProvider>
                    </SDKProvider>
                  </RouteProvider>
                </ToastProvider>
              </KVProvider>
            </ArgsProvider>
          </TuiConfigProvider>
        </OpencodeKeymapProvider>
      </TestTuiContexts>
    )
  }

  const app = await testRender(() => <Harness />, { width: 100, height: 25, kittyKeyboard: true })
  async function frame(text: string) {
    for (let attempt = 0; attempt < 50; attempt++) {
      await app.renderOnce()
      if (app.captureCharFrame().includes(text)) return
      await Bun.sleep(10)
    }
    throw new Error(`did not render ${text}: ${app.captureCharFrame()}`)
  }
  for (let attempt = 0; attempt < 50; attempt++) {
    if (local) break
    await app.renderOnce()
    await Bun.sleep(10)
  }
  for (let attempt = 0; attempt < 50 && (!local.model.ready || !local.model.selectionReady); attempt++)
    await Bun.sleep(10)
  expect(local.model.ready).toBe(true)
  return {
    app,
    local,
    route,
    directory,
    dialog,
    frame,
    async saved(value: string) {
      for (let attempt = 0; attempt < 50; attempt++) {
        const file = Bun.file(path.join(tmp.path, "model.json"))
        if ((await file.exists()) && (await file.json()).variant["test/reasoner"] === value) return
        await Bun.sleep(10)
      }
      throw new Error("variant was not saved")
    },
    async cleanup() {
      app.renderer.destroy()
      await Bun.sleep(25)
      await tmp[Symbol.asyncDispose]()
    },
  }
}

test("reasoning control opens the picker, selects a level for the next prompt, and restores Default", async () => {
  const setup = await mount()
  try {
    await setup.app.mockMouse.click(3, 0)
    await setup.frame("Select reasoning level")
    expect(setup.app.captureCharFrame().replace(/\s+/g, " ")).toContain("Does not interrupt the current run")
    setup.app.mockInput.pressArrow("down")
    setup.app.mockInput.pressEnter()
    await setup.frame("Reasoning: low")
    expect(setup.local.model.variant.current()).toBe("low")
    expect(setup.dialog.stack).toHaveLength(0)
    await setup.saved("low")
    await setup.app.mockMouse.click(3, 0)
    await setup.frame("Select reasoning level")
    setup.app.mockInput.pressArrow("up")
    setup.app.mockInput.pressEnter()
    await setup.frame("Reasoning: default")
    expect(setup.local.model.variant.current()).toBeUndefined()
    await setup.saved("default")
  } finally {
    await setup.cleanup()
  }
})

test("picker cancel keeps the level, selections stay per model, and models without variants hide the control", async () => {
  const setup = await mount()
  try {
    setup.local.model.variant.set("high")
    await setup.frame("Reasoning: high")
    await setup.app.mockMouse.click(3, 0, 2)
    expect(setup.dialog.stack).toHaveLength(0)
    await setup.app.mockMouse.click(3, 0)
    await setup.frame("Select reasoning level")
    setup.app.mockInput.pressEscape()
    await setup.frame("Reasoning: high")
    expect(setup.local.model.variant.current()).toBe("high")
    setup.local.model.set({ providerID: "test", modelID: "plain" })
    await setup.frame("Variant: default")
    await setup.app.mockMouse.click(3, 0)
    await setup.frame("Select model variant")
    setup.app.mockInput.pressEscape()
    setup.local.model.set({ providerID: "test", modelID: "reasoner" })
    await setup.frame("Reasoning: high")
    setup.local.model.set({ providerID: "test", modelID: "fixed" })
    await setup.app.renderOnce()
    expect(setup.app.captureCharFrame()).not.toContain("Variant:")
    expect(setup.app.captureCharFrame()).not.toContain("Reasoning:")
    await setup.saved("high")
  } finally {
    await setup.cleanup()
  }
})

async function waitForSelection(setup: Awaited<ReturnType<typeof mount>>) {
  for (let attempt = 0; attempt < 50 && !setup.local.model.selectionReady; attempt++) await Bun.sleep(10)
  expect(setup.local.model.selectionReady).toBe(true)
}

async function savedSession(directory: string, sessionID: string, modelID: string, variant: string) {
  const filename = path.join(directory, "session-model", `session-${sessionID}.json`)
  for (let attempt = 0; attempt < 50; attempt++) {
    const file = Bun.file(filename)
    if (await file.exists()) {
      const saved = await file.json()
      if (saved.model.modelID === modelID && saved.variants[`test/${modelID}`] === variant) return
    }
    await Bun.sleep(10)
  }
  throw new Error(
    `session selection was not saved: ${sessionID} expected ${modelID}/${variant}; disk ${await Bun.file(filename)
      .text()
      .catch(() => "missing")}`,
  )
}

test("unsent model and reasoning choices survive client restart separately for each session", async () => {
  await using tmp = await tmpdir()
  const first = await mount({ directory: tmp.path, sessionID: "ses_first" })
  try {
    first.local.model.set({ providerID: "test", modelID: "plain" }, { recent: true })
    first.local.model.variant.set("fast")
    await savedSession(tmp.path, "ses_first", "plain", "fast")
    first.route.navigate({ type: "session", sessionID: "ses_second" })
    await waitForSelection(first)
    expect(first.local.model.current()?.modelID).toBe("reasoner")
    first.local.model.variant.set("high")
    await savedSession(tmp.path, "ses_second", "reasoner", "high")
    first.route.navigate({ type: "session", sessionID: "ses_first" })
    await waitForSelection(first)
    first.local.model.restore({ providerID: "test", modelID: "reasoner" }, "low")
    expect(first.local.model.current()?.modelID).toBe("plain")
    expect(first.local.model.variant.current()).toBe("fast")
  } finally {
    await first.cleanup()
  }
  const reopened = await mount({ directory: tmp.path, sessionID: "ses_first" })
  try {
    expect(reopened.local.model.current()?.modelID).toBe("plain")
    expect(reopened.local.model.variant.current()).toBe("fast")
    reopened.route.navigate({ type: "session", sessionID: "ses_second" })
    await waitForSelection(reopened)
    expect(reopened.local.model.variant.current()).toBe("high")
    reopened.local.model.variant.set(undefined)
    await savedSession(tmp.path, "ses_second", "reasoner", "default")
  } finally {
    await reopened.cleanup()
  }
  const defaulted = await mount({ directory: tmp.path, sessionID: "ses_second" })
  try {
    defaulted.local.model.restore({ providerID: "test", modelID: "reasoner" }, "high")
    expect(defaulted.local.model.variant.current()).toBeUndefined()
  } finally {
    await defaulted.cleanup()
  }
})

test("history initializes missing preferences but never overwrites explicit choices; shortcuts and CLI persist", async () => {
  await using tmp = await tmpdir()
  const setup = await mount({ directory: tmp.path, sessionID: "ses_history" })
  try {
    setup.local.model.restore({ providerID: "test", modelID: "plain" }, "fast")
    expect(setup.local.model.current()?.modelID).toBe("plain")
    setup.local.model.set({ providerID: "test", modelID: "reasoner" }, { recent: true })
    setup.local.model.set({ providerID: "test", modelID: "plain" }, { recent: true })
    setup.local.model.cycle(1)
    expect(setup.local.model.current()?.modelID).toBe("reasoner")
    setup.local.model.variant.cycle()
    await savedSession(tmp.path, "ses_history", "reasoner", "low")
    setup.local.model.toggleFavorite({ providerID: "test", modelID: "plain" })
    setup.local.model.cycleFavorite(1)
    await savedSession(tmp.path, "ses_history", "plain", "fast")
  } finally {
    await setup.cleanup()
  }
  const override = await mount({ directory: tmp.path, sessionID: "ses_history", model: "test/fixed" })
  try {
    expect(override.local.model.current()?.modelID).toBe("fixed")
    override.local.model.set({ providerID: "test", modelID: "plain" })
    expect(override.local.model.variant.current()).toBe("fast")
    await savedSession(tmp.path, "ses_history", "plain", "fast")
  } finally {
    await override.cleanup()
  }
})

test("new-session adoption keeps the submitted choice, per-model levels remain scoped, and unavailable models fall back", async () => {
  const setup = await mount()
  try {
    setup.local.model.set({ providerID: "test", modelID: "reasoner" })
    setup.local.model.variant.set("high")
    setup.local.model.remember("ses_new", setup.local.model.current()!, setup.local.model.variant.current())
    setup.route.navigate({ type: "session", sessionID: "ses_new" })
    await waitForSelection(setup)
    expect(setup.local.model.variant.current()).toBe("high")
    setup.local.model.set({ providerID: "test", modelID: "plain" })
    setup.local.model.variant.set("fast")
    setup.local.model.set({ providerID: "test", modelID: "reasoner" })
    expect(setup.local.model.variant.current()).toBe("high")
    await savedSession(setup.directory, "ses_new", "reasoner", "high")
    setup.local.model.remember("ses_missing", { providerID: "test", modelID: "removed" }, "gone")
    setup.route.navigate({ type: "session", sessionID: "ses_missing" })
    await waitForSelection(setup)
    expect(setup.local.model.current()?.modelID).toBe("reasoner")
    expect(setup.local.model.variant.current()).toBeUndefined()
  } finally {
    await setup.cleanup()
  }
})

test("CLI preserves saved reasoning and does not replace a new session's submitted model", async () => {
  await using tmp = await tmpdir()
  const first = await mount({ directory: tmp.path, sessionID: "ses_cli" })
  try {
    first.local.model.variant.set("high")
    await savedSession(tmp.path, "ses_cli", "reasoner", "high")
  } finally {
    await first.cleanup()
  }
  const reopened = await mount({ directory: tmp.path, sessionID: "ses_cli", model: "test/reasoner" })
  try {
    expect(reopened.local.model.variant.current()).toBe("high")
  } finally {
    await reopened.cleanup()
  }
  const home = await mount({ model: "test/reasoner" })
  try {
    home.local.model.set({ providerID: "test", modelID: "plain" })
    home.local.model.variant.set("fast")
    home.local.model.remember("ses_new_cli", home.local.model.current()!, home.local.model.variant.current())
    home.route.navigate({ type: "session", sessionID: "ses_new_cli" })
    await waitForSelection(home)
    expect(home.local.model.current()?.modelID).toBe("plain")
    expect(home.local.model.variant.current()).toBe("fast")
  } finally {
    await home.cleanup()
  }
})
