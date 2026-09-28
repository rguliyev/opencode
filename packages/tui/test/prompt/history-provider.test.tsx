import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { mkdtemp, rm } from "fs/promises"
import path from "path"
import { tmpdir } from "os"
import { TuiPathsProvider, TuiStartupProvider } from "../../src/context/runtime"
import { RouteProvider } from "../../src/context/route"
import { SDKProvider } from "../../src/context/sdk"
import { PromptHistoryProvider, usePromptHistory } from "../../src/prompt/history"

test("session prompt history survives a new attach without mixing sessions", async () => {
  const state = await mkdtemp(path.join(tmpdir(), "opencode-session-history-"))
  let history: ReturnType<typeof usePromptHistory>
  const render = () =>
    testRender(
      () => (
        <TuiPathsProvider value={{ cwd: state, home: state, state, worktree: state }}>
          <TuiStartupProvider value={{ skipInitialLoading: true }}>
            <RouteProvider initialRoute={{ type: "session", sessionID: "ses_alpha" }}>
              <SDKProvider
                url="http://history.test"
                directory={state}
                fetch={Object.assign(async () => Response.json([]), { preconnect() {} })}
                events={{ subscribe: async () => () => {} }}
              >
                <PromptHistoryProvider>
                  {(() => {
                    history = usePromptHistory()
                    return <text>history ready</text>
                  })()}
                </PromptHistoryProvider>
              </SDKProvider>
            </RouteProvider>
          </TuiStartupProvider>
        </TuiPathsProvider>
      ),
      { width: 30, height: 3 },
    )

  try {
    const first = await render()
    try {
      await first.renderOnce()
      history!.append({ input: "alpha prompt", parts: [] }, "ses_alpha")
      history!.append({ input: "beta prompt", parts: [] }, "ses_beta")
      for (let attempt = 0; attempt < 50; attempt++) {
        const file = Bun.file(path.join(state, "prompt-history.json"))
        if (await file.exists()) {
          const entries = await file.json()
          if (entries.length === 2) break
        }
        await Bun.sleep(10)
      }
      expect((await Bun.file(path.join(state, "prompt-history.json")).json()).length).toBe(2)
    } finally {
      first.renderer.destroy()
    }

    const second = await render()
    try {
      await second.renderOnce()
      let alpha: ReturnType<typeof history.move>
      for (let attempt = 0; attempt < 50 && !alpha; attempt++) {
        alpha = history!.move(-1, "", "ses_alpha")
        if (!alpha) await Bun.sleep(10)
      }
      expect(alpha?.input).toBe("alpha prompt")
      expect(history!.move(-1, "", "ses_beta")?.input).toBe("beta prompt")
      expect(history!.move(-1, "")?.input).toBeUndefined()
    } finally {
      second.renderer.destroy()
    }
  } finally {
    await rm(state, { recursive: true, force: true })
  }
})
