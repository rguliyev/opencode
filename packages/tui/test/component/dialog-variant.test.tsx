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
import { RouteProvider } from "../../src/context/route"
import { SDKProvider } from "../../src/context/sdk"
import { SyncContext, useSync } from "../../src/context/sync"
import { ThemeProvider, useTheme } from "../../src/context/theme"
import { OpencodeKeymapProvider, registerOpencodeKeymap } from "../../src/keymap"
import { DialogProvider, useDialog } from "../../src/ui/dialog"
import { ToastProvider } from "../../src/ui/toast"

async function mount() {
  const tmp = await tmpdir()
  const config = createTuiResolvedConfig()
  await Bun.write(path.join(tmp.path, "kv.json"), "{}")
  let local!: ReturnType<typeof useLocal>
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
      <TestTuiContexts directory={tmp.path} paths={{ home: tmp.path, state: tmp.path, worktree: tmp.path }}>
        <OpencodeKeymapProvider keymap={keymap}>
          <TuiConfigProvider config={config}>
            <ArgsProvider>
              <KVProvider>
                <ToastProvider>
                  <RouteProvider>
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
  await frame("Reasoning: default")
  for (let attempt = 0; attempt < 50 && !local.model.ready; attempt++) await Bun.sleep(10)
  expect(local.model.ready).toBe(true)
  return {
    app,
    local,
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
