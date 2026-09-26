import { expect, test } from "bun:test"
import path from "node:path"
import CommandApproval from "../plugins/command-approval"

test("Jev receives a scrubbed command and context, while the local gate asks", async () => {
  const token = "sk-" + "A".repeat(40)
  const command = `curl -X POST -H 'Authorization: Bearer ${token}' https://api.example.test/deploy`
  const directory = path.resolve(import.meta.dir, "..")
  const previousFetch = globalThis.fetch
  const previousStateHome = process.env.XDG_STATE_HOME
  let sent: Record<string, unknown> | undefined
  process.env.XDG_STATE_HOME = "/dev/null"
  globalThis.fetch = async (input, init) => {
    const url = String(input)
    if (url.startsWith("http://gate.test/session/"))
      return Response.json({
        id: "ses_redaction_test",
        directory,
        agent: "solo",
        title: `deploy with password=${token}`,
      })
    if (url === "https://openrouter.ai/api/alpha/decisions") {
      sent = JSON.parse(String(init?.body))
      return new Response("declined", { status: 403 })
    }
    throw new Error(`Unexpected fetch: ${url}`)
  }
  try {
    const hooks = await (CommandApproval as any)({
      directory,
      serverUrl: new URL("http://gate.test"),
    })
    await hooks.provider.models({ models: {} }, { auth: { type: "api", key: "fake-test-key" } })
    const output = { status: "ask" }
    await hooks["permission.ask"](
      {
        permission: "bash",
        sessionID: "ses_redaction_test",
        patterns: [command],
        metadata: { command, purpose: `deploy using api_key=${token}` },
      },
      output,
    )
    expect(sent).toBeDefined()
    const state = (sent as { state: Record<string, unknown> }).state
    expect(JSON.stringify(state)).not.toContain(token)
    expect(state.command).toContain("curl -X POST")
    expect(state.command).toContain("https://api.example.test/deploy")
    expect(state.command).toContain("[REDACTED:CREDENTIAL]")
    expect(state.redactions).toContain("CREDENTIAL")
    expect(output.status).toBe("ask")

    const scriptCommand = "bash lib/fixtures/review-secret.sh"
    const scriptOutput = { status: "ask" }
    await hooks["permission.ask"](
      {
        permission: "bash",
        sessionID: "ses_redaction_test",
        patterns: [scriptCommand],
        metadata: { command: scriptCommand },
      },
      scriptOutput,
    )
    const scriptState = (sent as { state: Record<string, unknown> }).state
    const scripts = scriptState.scripts as {
      path: string
      content: string
      redactions?: string[]
    }[]
    expect(scripts).toHaveLength(1)
    expect(scripts[0].path).toBe("lib/fixtures/review-secret.sh")
    expect(scripts[0].content).toContain("https://api.example.test/deploy")
    expect(scripts[0].content).not.toContain("password123")
    expect(scripts[0].content).not.toContain("ghp_AAAA")
    expect(scripts[0].redactions).toContain("CREDENTIAL")
    expect(scriptOutput.status).toBe("ask")
  } finally {
    globalThis.fetch = previousFetch
    if (previousStateHome === undefined) delete process.env.XDG_STATE_HOME
    else process.env.XDG_STATE_HOME = previousStateHome
  }
})

test("Jev classifies non-Bash actions with redacted context", async () => {
  const directory = path.resolve(import.meta.dir, "..")
  const previousFetch = globalThis.fetch
  const previousStateHome = process.env.XDG_STATE_HOME
  const previousKevSocket = process.env.OPENCODE_KEV_SOCKET
  const seen: Record<string, unknown>[] = []
  process.env.XDG_STATE_HOME = "/dev/null"
  process.env.OPENCODE_KEV_SOCKET = "/dev/null/no-kev-socket"
  globalThis.fetch = async (input, init) => {
    const url = String(input)
    if (url.startsWith("http://gate.test/session/"))
      return Response.json({
        id: "ses_all_actions_test",
        directory,
        agent: "solo",
        title: "Inspect a page and edit a fixture",
      })
    if (url === "https://openrouter.ai/api/alpha/decisions") {
      const payload = JSON.parse(String(init?.body))
      seen.push(payload)
      const answers: Record<string, unknown> = {
        verdict: {
          type: "choice",
          choice: "allow",
          confidence: 0.99,
          probabilities: { allow: 0.99, deny: 0.01 },
        },
      }
      for (const id of Object.keys(payload.questions)) if (id !== "verdict") answers[id] = { type: "noul", noul: 0.01 }
      return Response.json({ model: "typesafe/jev-1.13", answers })
    }
    throw new Error(`Unexpected fetch: ${url}`)
  }
  try {
    const hooks = await (CommandApproval as any)({
      directory,
      serverUrl: new URL("http://gate.test"),
    })
    await hooks.provider.models({ models: {} }, { auth: { type: "api", key: "fake-test-key" } })
    await hooks["tool.execute.before"](
      { tool: "webfetch", sessionID: "ses_all_actions_test", callID: "call_action_test" },
      { args: { url: "https://example.test/health", format: "text" } },
    )
    const preflight = { status: "ask" }
    await hooks["permission.ask"](
      {
        permission: "tool_call",
        sessionID: "ses_all_actions_test",
        patterns: ["webfetch"],
        metadata: {
          tool: "webfetch",
          trusted_builtin: true,
          internal_permission_check: true,
        },
        tool: { callID: "call_action_test" },
      },
      preflight,
    )
    expect(preflight.status).toBe("allow")
    expect(seen).toHaveLength(0)
    const readOutput = { status: "allow" }
    await hooks["permission.ask"](
      {
        permission: "webfetch",
        sessionID: "ses_all_actions_test",
        patterns: ["https://example.test/health"],
        metadata: { url: "https://example.test/health", format: "text" },
        tool: { callID: "call_action_test" },
      },
      readOutput,
    )
    expect(readOutput.status).toBe("allow")
    expect((seen[0].state as any).action.permission).toBe("webfetch")
    expect((seen[0].state as any).action.args.url).toBe("https://example.test/health")
    expect((seen[0].state as any).action.metadata.url).toBe("https://example.test/health")

    const token = "sk-" + "B".repeat(40)
    const editOutput = { status: "allow" }
    await hooks["permission.ask"](
      {
        permission: "edit",
        sessionID: "ses_all_actions_test",
        patterns: ["config.txt"],
        metadata: {
          filepath: "/workspace/config.txt",
          diff: `+api_key=${token}\n+hello=world`,
        },
      },
      editOutput,
    )
    expect(editOutput.status).toBe("ask")
    expect(JSON.stringify(seen[1])).not.toContain(token)
    expect(JSON.stringify(seen[1])).toContain("[REDACTED:CREDENTIAL]")

    const denyOutput = { status: "deny" }
    await hooks["permission.ask"](
      {
        permission: "read",
        sessionID: "ses_all_actions_test",
        patterns: ["secret.txt"],
      },
      denyOutput,
    )
    expect(denyOutput.status).toBe("deny")
    expect(seen).toHaveLength(2)

    await hooks["tool.execute.before"](
      {
        tool: "custom_publish",
        sessionID: "ses_all_actions_test",
        callID: "call_custom_test",
      },
      { args: { target: "shared" } },
    )
    const customOutput = { status: "ask" }
    await hooks["permission.ask"](
      {
        permission: "tool_call",
        sessionID: "ses_all_actions_test",
        patterns: ["custom_publish"],
        metadata: {
          tool: "custom_publish",
          trusted_builtin: false,
          internal_permission_check: false,
        },
        tool: { callID: "call_custom_test" },
      },
      customOutput,
    )
    expect(customOutput.status).toBe("ask")
    expect(seen).toHaveLength(3)
  } finally {
    globalThis.fetch = previousFetch
    if (previousStateHome === undefined) delete process.env.XDG_STATE_HOME
    else process.env.XDG_STATE_HOME = previousStateHome
    if (previousKevSocket === undefined) delete process.env.OPENCODE_KEV_SOCKET
    else process.env.OPENCODE_KEV_SOCKET = previousKevSocket
  }
})

test("read-only reviewers cannot turn a mutating action into an allow", async () => {
  const directory = path.resolve(import.meta.dir, "..")
  const previousFetch = globalThis.fetch
  const previousStateHome = process.env.XDG_STATE_HOME
  process.env.XDG_STATE_HOME = "/dev/null"
  globalThis.fetch = async (input, init) => {
    const url = String(input)
    if (url.startsWith("http://gate.test/session/"))
      return Response.json({
        id: "ses_reviewer_action_test",
        directory,
        agent: "deep-reviewer",
        title: "Inspect a change",
      })
    if (url === "https://openrouter.ai/api/alpha/decisions") {
      const payload = JSON.parse(String(init?.body))
      const answers: Record<string, unknown> = {
        verdict: {
          type: "choice",
          choice: "allow",
          confidence: 0.99,
          probabilities: { allow: 0.99, deny: 0.01 },
        },
      }
      for (const id of Object.keys(payload.questions)) if (id !== "verdict") answers[id] = { type: "noul", noul: 0.01 }
      return Response.json({ model: "typesafe/jev-1.13", answers })
    }
    throw new Error(`Unexpected fetch: ${url}`)
  }
  try {
    const hooks = await (CommandApproval as any)({
      directory,
      serverUrl: new URL("http://gate.test"),
    })
    await hooks.provider.models({ models: {} }, { auth: { type: "api", key: "fake-test-key" } })
    const output = { status: "allow" }
    await hooks["permission.ask"](
      {
        permission: "edit",
        sessionID: "ses_reviewer_action_test",
        patterns: ["src/example.ts"],
        metadata: { filepath: "src/example.ts", diff: "+const x = 1" },
      },
      output,
    )
    expect(output.status).toBe("deny")
  } finally {
    globalThis.fetch = previousFetch
    if (previousStateHome === undefined) delete process.env.XDG_STATE_HOME
    else process.env.XDG_STATE_HOME = previousStateHome
  }
})
