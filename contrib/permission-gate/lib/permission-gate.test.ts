import { expect, test } from "bun:test"
import { mkdtempSync, rmSync, symlinkSync } from "node:fs"
import { createServer } from "node:net"
import { tmpdir } from "node:os"
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
    if (url.includes("/session/ses_redaction_test/message?"))
      return Response.json([{ info: { role: "user" }, parts: [{ type: "text", text: "Inspect the local fixture." }] }])
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

    await hooks["tool.execute.before"](
      { tool: "skill", sessionID: "ses_redaction_test", callID: "call_skill_redaction" },
      { args: { name: "example" } },
    )
    const skillOutput = { status: "allow" }
    await hooks["permission.ask"](
      {
        permission: "skill",
        sessionID: "ses_redaction_test",
        patterns: ["example"],
        metadata: {
          name: "example",
          location: "/skills/example/SKILL.md",
          content: `Use api_key=${token} to authenticate.`,
          core_trusted_builtin: true,
        },
        tool: { callID: "call_skill_redaction" },
      },
      skillOutput,
    )
    expect(skillOutput.status).toBe("ask")
    expect(JSON.stringify(sent)).not.toContain(token)
    expect(JSON.stringify(sent)).toContain("[REDACTED:CREDENTIAL]")
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
  const order: string[] = []
  const kevRequests: Record<string, unknown>[] = []
  let bashDeny = false
  const socketDir = mkdtempSync(path.join(tmpdir(), "opencode-kev-gate-"))
  const kev = createServer((socket) => {
    connections += 1
    order.push("kev")
    let data = ""
    socket.on("data", (chunk) => {
      data += chunk.toString("utf8")
      if (!data.includes("\n")) return
      const request = JSON.parse(data.split("\n", 1)[0])
      kevRequests.push(request)
      socket.end(
        JSON.stringify({
          version: 2,
          status: request.kind === "bash" ? "score" : "unsupported_action",
          ...(request.kind === "bash" ? { p_allow: 0.99 } : {}),
          context_status: "received",
        }) + "\n",
      )
    })
  })
  let connections = 0
  process.env.XDG_STATE_HOME = "/dev/null"
  process.env.OPENCODE_KEV_SOCKET = path.join(socketDir, "score.sock")
  await new Promise<void>((resolve, reject) => {
    kev.once("error", reject)
    kev.listen(process.env.OPENCODE_KEV_SOCKET, resolve)
  })
  globalThis.fetch = async (input, init) => {
    const url = String(input)
    if (url.includes("/session/ses_all_actions_test/message?"))
      return Response.json([
        { info: { role: "user" }, parts: [{ type: "text", text: "Run printf hello in the local worktree." }] },
      ])
    if (url.startsWith("http://gate.test/session/"))
      return Response.json({
        id: "ses_all_actions_test",
        directory,
        agent: "solo",
        title: "Inspect a page and edit a fixture",
      })
    if (url === "https://openrouter.ai/api/alpha/decisions") {
      order.push("jev")
      const payload = JSON.parse(String(init?.body))
      seen.push(payload)
      const answers: Record<string, unknown> = {
        verdict: {
          type: "choice",
          choice: bashDeny ? "deny" : "allow",
          confidence: bashDeny ? 0.24 : 0.99,
          probabilities: bashDeny ? { allow: 0.38, deny: 0.62 } : { allow: 0.99, deny: 0.01 },
        },
      }
      for (const id of Object.keys(payload.questions)) if (id !== "verdict") answers[id] = { type: "noul", noul: 0.01 }
      return Response.json({ model: "typesafe/jev-1.13", answers })
    }
    if (url === "https://openrouter.ai/api/v1/chat/completions") {
      order.push("luna")
      return Response.json({
        model: "openai/gpt-6-luna",
        choices: [
          {
            finish_reason: "stop",
            message: {
              content: JSON.stringify({ choice: "allow", reason: "The requested local command is in scope." }),
            },
          },
        ],
      })
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
    expect(connections).toBe(1)
    expect(order).toEqual(["kev", "jev"])
    expect(kevRequests[0].version).toBe(2)
    expect(kevRequests[0].kind).toBe("action")
    expect(JSON.parse(kevRequests[0].state.evidence).permission).toBe("webfetch")
    expect(kevRequests[0].state.context.human_request).toBe("Run printf hello in the local worktree.")
    expect((seen[0].state as any).action.permission).toBe("webfetch")
    expect((seen[0].state as any).action.args.url).toBe("https://example.test/health")
    expect((seen[0].state as any).action.metadata.url).toBe("https://example.test/health")

    const configuredExternal = { status: "allow" }
    await hooks["permission.ask"](
      {
        permission: "external_directory",
        sessionID: "ses_all_actions_test",
        patterns: [path.join(directory, "*")],
        metadata: { filepath: directory },
      },
      configuredExternal,
    )
    expect(configuredExternal.status).toBe("allow")
    expect(seen).toHaveLength(1)

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
    expect(JSON.stringify(kevRequests[1])).not.toContain(token)
    expect(JSON.stringify(kevRequests[1])).toContain("[REDACTED:CREDENTIAL]")

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
    expect(connections).toBe(3)

    // The same live socket must still receive eligible Bash commands.
    bashDeny = true
    order.length = 0
    await hooks["tool.execute.before"](
      { tool: "bash", sessionID: "ses_all_actions_test", callID: "call_bash_test" },
      { args: { command: "printf hello" } },
    )
    const bashOutput = { status: "ask", message: "" }
    await hooks["permission.ask"](
      {
        permission: "bash",
        sessionID: "ses_all_actions_test",
        patterns: ["printf hello"],
        metadata: { command: "printf hello" },
        tool: { callID: "call_bash_test" },
      },
      bashOutput,
    )
    expect(bashOutput.status).toBe("ask")
    expect(bashOutput.message).toContain("Luna advises allow")
    expect(seen).toHaveLength(4)
    expect(connections).toBe(4)
    expect(order).toEqual(["kev", "jev", "luna"])
    expect(kevRequests[3].kind).toBe("bash")
    expect(kevRequests[3].state.context).toMatchObject({
      agent: "solo",
      command_count: 1,
      human_request: "Run printf hello in the local worktree.",
    })
    const kevContext = kevRequests[3].state.context
    expect(kevContext && typeof kevContext === "object" && "full_command" in kevContext).toBe(false)
  } finally {
    await new Promise<void>((resolve) => kev.close(() => resolve()))
    rmSync(socketDir, { recursive: true, force: true })
    globalThis.fetch = previousFetch
    if (previousStateHome === undefined) delete process.env.XDG_STATE_HOME
    else process.env.XDG_STATE_HOME = previousStateHome
    if (previousKevSocket === undefined) delete process.env.OPENCODE_KEV_SOCKET
    else process.env.OPENCODE_KEV_SOCKET = previousKevSocket
  }
})

test("Jev receives paginated root human context and a distinct subagent task", async () => {
  const directory = path.resolve(import.meta.dir, "..")
  const previousFetch = globalThis.fetch
  const previousStateHome = process.env.XDG_STATE_HOME
  let jevContext: Record<string, unknown> | undefined
  const requests: string[] = []
  let childTaskAvailable = true
  let childTaskContainsPII = false
  let rootHumanAvailable = true
  const reviewCount = () => requests.filter((request) => request.startsWith("/api/alpha/decisions")).length
  process.env.XDG_STATE_HOME = "/dev/null"
  globalThis.fetch = async (input, init) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url)
    requests.push(url.pathname + url.search)
    if (url.pathname === "/session/ses_child_context/message")
      return Response.json(
        childTaskAvailable
          ? [
              {
                info: { role: "user" },
                parts: [
                  {
                    type: "text",
                    text: childTaskContainsPII
                      ? "Inspect patient alice@example.test's local fixture."
                      : "Inspect the local fixture and report its status.",
                  },
                ],
              },
            ]
          : [{ info: { role: "assistant" }, parts: [{ type: "text", text: "working" }] }],
      )
    if (url.pathname === "/session/ses_root_context/message") {
      if (!rootHumanAvailable)
        return Response.json([{ info: { role: "assistant" }, parts: [{ type: "text", text: "working" }] }])
      if (url.searchParams.get("before") === "older-root-page")
        return Response.json([
          { info: { role: "user" }, parts: [{ type: "text", text: "Check the local fixture." }] },
          { info: { role: "user" }, parts: [{ type: "text", text: "Yes, do it." }] },
        ])
      if (url.searchParams.get("limit") === "16")
        return Response.json(
          Array.from({ length: 16 }, () => ({
            info: { role: "assistant" },
            parts: [{ type: "text", text: "x".repeat(20_000) }],
          })),
        )
      return Response.json([{ info: { role: "assistant" }, parts: [{ type: "text", text: "working" }] }], {
        headers: { "X-Next-Cursor": "older-root-page" },
      })
    }
    if (url.pathname === "/session/ses_child_context")
      return Response.json({ id: "ses_child_context", directory, agent: "implementer", parentID: "ses_root_context" })
    if (url.pathname === "/session/ses_root_context")
      return Response.json({ id: "ses_root_context", directory, agent: "orchestrator" })
    if (url.href === "https://openrouter.ai/api/alpha/decisions") {
      if (typeof init?.body !== "string") throw new Error("Missing Jev request body")
      const payload = JSON.parse(init.body)
      jevContext = payload.state.context
      const answers: Record<string, unknown> = {
        verdict: { type: "choice", choice: "allow", confidence: 0.99, probabilities: { allow: 0.99, deny: 0.01 } },
      }
      for (const id of Object.keys(payload.questions)) if (id !== "verdict") answers[id] = { type: "noul", noul: 0.01 }
      return Response.json({ model: "typesafe/jev-1.13", answers })
    }
    throw new Error(`Unexpected fetch: ${url.href}`)
  }
  try {
    const hooks = await (CommandApproval as any)({ directory, serverUrl: new URL("http://gate.test") })
    await hooks.provider.models({ models: {} }, { auth: { type: "api", key: "fake-test-key" } })
    await hooks["tool.execute.before"](
      { tool: "read", sessionID: "ses_child_context", callID: "call_child_context" },
      { args: { filePath: "fixture.txt" } },
    )
    const output = { status: "ask" }
    await hooks["permission.ask"](
      {
        permission: "read",
        sessionID: "ses_child_context",
        patterns: ["fixture.txt"],
        metadata: { filepath: "fixture.txt" },
        tool: { callID: "call_child_context" },
      },
      output,
    )
    expect(output.status).toBe("allow")
    expect(jevContext?.human_request).toBe("Yes, do it.")
    expect(jevContext?.human_history).toContain("Check the local fixture.")
    expect(jevContext?.delegated_task).toBe("Inspect the local fixture and report its status.")
    expect(requests.some((request) => request.includes("limit=8"))).toBe(true)
    expect(requests.some((request) => request.includes("before=older-root-page"))).toBe(true)
    expect(reviewCount()).toBe(1)

    childTaskAvailable = false
    const missingTask = { status: "allow" }
    await hooks["permission.ask"](
      {
        permission: "read",
        sessionID: "ses_child_context",
        patterns: ["fixture.txt"],
        metadata: { filepath: "fixture.txt" },
        tool: { callID: "call_child_context" },
      },
      missingTask,
    )
    expect(missingTask.status).toBe("ask")
    expect(reviewCount()).toBe(1)

    childTaskAvailable = true
    rootHumanAvailable = false
    const missingHuman = { status: "allow" }
    await hooks["permission.ask"](
      {
        permission: "read",
        sessionID: "ses_child_context",
        patterns: ["fixture.txt"],
        metadata: { filepath: "fixture.txt" },
        tool: { callID: "call_child_context" },
      },
      missingHuman,
    )
    expect(missingHuman.status).toBe("ask")
    expect(reviewCount()).toBe(1)

    rootHumanAvailable = true
    childTaskContainsPII = true
    const piiTask = { status: "allow" }
    await hooks["permission.ask"](
      {
        permission: "read",
        sessionID: "ses_child_context",
        patterns: ["fixture.txt"],
        metadata: { filepath: "fixture.txt" },
        tool: { callID: "call_child_context" },
      },
      piiTask,
    )
    expect(piiTask.status).toBe("ask")
    expect(reviewCount()).toBe(1)
    expect(JSON.stringify(jevContext)).not.toContain("alice@example.test")
  } finally {
    globalThis.fetch = previousFetch
    if (previousStateHome === undefined) delete process.env.XDG_STATE_HOME
    else process.env.XDG_STATE_HOME = previousStateHome
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

test("configured external-directory allow does not follow a symlink outside the allowlist", async () => {
  const directory = path.resolve(import.meta.dir, "..")
  const previousFetch = globalThis.fetch
  const previousStateHome = process.env.XDG_STATE_HOME
  const inside = mkdtempSync("/data/rguliyev/tmp/opencode/permission-gate-test-")
  const outside = mkdtempSync(path.join(tmpdir(), "permission-gate-outside-"))
  const link = path.join(inside, "escape")
  symlinkSync(outside, link, "dir")
  process.env.XDG_STATE_HOME = "/dev/null"
  globalThis.fetch = async () => new Response("missing", { status: 404 })
  try {
    const hooks = await (CommandApproval as any)({ directory, serverUrl: new URL("http://gate.test") })
    const output = { status: "allow" }
    await hooks["permission.ask"](
      {
        permission: "external_directory",
        sessionID: "ses_symlink_test",
        patterns: [path.join(link, "*")],
        metadata: { filepath: link },
      },
      output,
    )
    expect(output.status).toBe("ask")
  } finally {
    globalThis.fetch = previousFetch
    if (previousStateHome === undefined) delete process.env.XDG_STATE_HOME
    else process.env.XDG_STATE_HOME = previousStateHome
    rmSync(inside, { recursive: true, force: true })
    rmSync(outside, { recursive: true, force: true })
  }
})

test("Luna resolves only low-risk Jev escalations with trusted human context and strict JSON", async () => {
  const directory = path.resolve(import.meta.dir, "..")
  const previousFetch = globalThis.fetch
  const previousStateHome = process.env.XDG_STATE_HOME
  const previousKevSocket = process.env.OPENCODE_KEV_SOCKET
  const seen: string[] = []
  let lunaContent = JSON.stringify({ choice: "allow", reason: "The requested local file listing is in scope." })
  let jevRisk = 0.01
  let jevConfidence = 0.24
  let latestHumanText: string | undefined
  let lunaState: Record<string, unknown> | undefined
  let jevState: Record<string, unknown> | undefined
  process.env.XDG_STATE_HOME = "/dev/null"
  process.env.OPENCODE_KEV_SOCKET = "/dev/null/no-kev-socket"
  globalThis.fetch = async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url
    if (url.includes("/session/ses_luna_test/message?"))
      return Response.json([
        { info: { role: "user" }, parts: [{ type: "text", text: "Check whether src/main.ts exists." }] },
        { info: { role: "user" }, parts: [{ type: "text", text: "Synthetic reminder", synthetic: true }] },
        ...(latestHumanText ? [{ info: { role: "user" }, parts: [{ type: "text", text: latestHumanText }] }] : []),
      ])
    if (url.startsWith("http://gate.test/session/"))
      return Response.json({ id: "ses_luna_test", directory, agent: "solo", title: "Update README" })
    if (url === "https://openrouter.ai/api/alpha/decisions") {
      seen.push("jev")
      if (typeof init?.body !== "string") throw new Error("Missing Jev request body")
      const payload = JSON.parse(init.body)
      jevState = payload.state
      const answers: Record<string, unknown> = {
        verdict: {
          type: "choice",
          choice: "deny",
          confidence: jevConfidence,
          probabilities: jevConfidence >= 0.6 ? { allow: 0.05, deny: 0.95 } : { allow: 0.38, deny: 0.62 },
        },
      }
      for (const id of Object.keys(payload.questions))
        if (id !== "verdict") answers[id] = { type: "noul", noul: id === "secrets" ? jevRisk : 0.01 }
      return Response.json({ model: "typesafe/jev-1.13", answers })
    }
    if (url === "https://openrouter.ai/api/v1/chat/completions") {
      seen.push("luna")
      if (typeof init?.body !== "string") throw new Error("Missing Luna request body")
      const payload = JSON.parse(init.body)
      lunaState = JSON.parse(payload.messages[1].content)
      return Response.json({
        model: "openai/gpt-6-luna",
        choices: [{ finish_reason: "stop", message: { content: lunaContent } }],
      })
    }
    throw new Error(`Unexpected fetch: ${url}`)
  }
  try {
    const hooks = await (CommandApproval as any)({ directory, serverUrl: new URL("http://gate.test") })
    await hooks.provider.models({ models: {} }, { auth: { type: "api", key: "fake-test-key" } })
    await hooks["tool.execute.before"](
      { tool: "glob", sessionID: "ses_luna_test", callID: "call_luna_glob" },
      { args: { pattern: "src/main.ts" } },
    )
    const request = {
      permission: "glob",
      sessionID: "ses_luna_test",
      patterns: ["src/main.ts"],
      metadata: {
        pattern: "src/main.ts",
        matched_paths: [path.join(directory, "src/main.ts")],
        truncated: false,
        core_trusted_builtin: true,
      },
      tool: { callID: "call_luna_glob" },
    }
    const allowed = { status: "ask" }
    await hooks["permission.ask"](request, allowed)
    expect(allowed.status).toBe("allow")
    expect(seen).toEqual(["jev", "luna"])
    const lunaAction = lunaState?.action
    expect(
      lunaAction && typeof lunaAction === "object" && "metadata" in lunaAction
        ? (lunaAction.metadata as { match_count?: unknown; matched_paths?: unknown }).match_count
        : undefined,
    ).toBe(1)
    expect(JSON.stringify(lunaState)).not.toContain("matched_paths")
    const lunaContext = lunaState?.context
    expect(
      lunaContext && typeof lunaContext === "object" && "human_request" in lunaContext
        ? lunaContext.human_request
        : undefined,
    ).toBe("Check whether src/main.ts exists.")
    expect(
      lunaContext && typeof lunaContext === "object" && "immediate_effect" in lunaContext
        ? lunaContext.immediate_effect
        : undefined,
    ).toContain("Reads local data")

    latestHumanText = "Build an isolated mock webhook fixture locally."
    await hooks["tool.execute.before"](
      { tool: "task", sessionID: "ses_luna_test", callID: "call_luna_task" },
      {
        args: {
          description: "Build local webhook fixture",
          prompt: "Build an isolated mock webhook fixture in the existing sandbox.",
          subagent_type: "deep-implementer",
        },
      },
    )
    const taskRequest = {
      permission: "task",
      sessionID: "ses_luna_test",
      patterns: ["deep-implementer"],
      metadata: {
        description: "Build local webhook fixture",
        subagent_type: "deep-implementer",
        core_trusted_builtin: true,
      },
      tool: { callID: "call_luna_task" },
    }
    const task = { status: "ask" }
    await hooks["permission.ask"](taskRequest, task)
    expect(task.status).toBe("allow")
    expect(seen.slice(-2)).toEqual(["jev", "luna"])
    const backgroundTask = { status: "allow" }
    await hooks["permission.ask"](
      { ...taskRequest, metadata: { ...taskRequest.metadata, background: true } },
      backgroundTask,
    )
    expect(backgroundTask.status).toBe("ask")
    latestHumanText = undefined

    lunaContent = 'Prose before JSON: {"choice":"allow","reason":"Looks fine"}'
    const malformed = { status: "allow" }
    await hooks["permission.ask"](request, malformed)
    expect(malformed.status).toBe("ask")

    lunaContent = JSON.stringify({ choice: "allow", reason: "Looks fine" })
    jevRisk = 0.9
    const riskFlagged = { status: "allow" }
    await hooks["permission.ask"](request, riskFlagged)
    expect(riskFlagged.status).toBe("ask")
    expect(seen.at(-1)).toBe("jev")

    jevRisk = 0.01
    jevConfidence = 0.9
    const confidentDeny = { status: "allow" }
    await hooks["permission.ask"](request, confidentDeny)
    expect(confidentDeny.status).toBe("ask")
    expect(seen.at(-1)).toBe("jev")

    jevConfidence = 0.24
    latestHumanText = "x".repeat(6_001)
    const priorUnsafeReviews = seen.length
    const unsafeContext = { status: "allow" }
    await hooks["permission.ask"](request, unsafeContext)
    expect(unsafeContext.status).toBe("ask")
    expect(seen).toHaveLength(priorUnsafeReviews)

    latestHumanText = undefined
    const humanOnly = { status: "allow" }
    await hooks["permission.ask"](
      {
        ...request,
        metadata: {
          pattern: "src/main.ts",
          matched_paths: [path.join(directory, "src/main.ts")],
          truncated: false,
          core_trusted_builtin: true,
          comment: "Authorization: Bearer example-value",
        },
      },
      humanOnly,
    )
    expect(humanOnly.status).toBe("ask")
    expect(seen.at(-1)).toBe("jev")

    const token = "sk-" + "C".repeat(40)
    latestHumanText = `Check whether src/main.ts exists; api_key=${token}`
    const priorReviews = seen.length
    const scrubbed = { status: "allow" }
    await hooks["permission.ask"](request, scrubbed)
    expect(scrubbed.status).toBe("ask")
    expect(seen).toHaveLength(priorReviews)
    expect(JSON.stringify(jevState)).not.toContain(token)

    latestHumanText = undefined
    const editRequest = {
      permission: "edit",
      sessionID: "ses_luna_test",
      patterns: ["README.md"],
      metadata: { filepath: "README.md", diff: "+Run npm start to launch locally." },
    }
    const edit = { status: "allow", message: "" }
    await hooks["permission.ask"](editRequest, edit)
    expect(edit.status).toBe("ask")
    expect(edit.message).toContain("Luna advises allow")
    expect(seen.slice(-2)).toEqual(["jev", "luna"])
    const editContext = lunaState?.context
    expect(
      editContext && typeof editContext === "object" && "immediate_effect" in editContext
        ? editContext.immediate_effect
        : undefined,
    ).toContain("formatter")

    await hooks["tool.execute.before"](
      { tool: "glob", sessionID: "ses_luna_test", callID: "call_luna_hidden" },
      { args: { pattern: "**/.env*" } },
    )
    const hidden = { status: "allow" }
    await hooks["permission.ask"](
      {
        permission: "glob",
        sessionID: "ses_luna_test",
        patterns: ["**/.env*"],
        metadata: { pattern: "**/.env*", matched_paths: [], truncated: false, core_trusted_builtin: true },
        tool: { callID: "call_luna_hidden" },
      },
      hidden,
    )
    expect(hidden.status).toBe("ask")

    await hooks["tool.execute.before"](
      { tool: "glob", sessionID: "ses_luna_test", callID: "call_luna_wildcard" },
      { args: { pattern: "**/*.ts" } },
    )
    const wildcard = { status: "allow" }
    await hooks["permission.ask"](
      {
        permission: "glob",
        sessionID: "ses_luna_test",
        patterns: ["**/*.ts"],
        metadata: {
          pattern: "**/*.ts",
          matched_paths: [path.join(directory, "Alice-1987-08-30.ts")],
          truncated: false,
          core_trusted_builtin: true,
        },
        tool: { callID: "call_luna_wildcard" },
      },
      wildcard,
    )
    expect(wildcard.status).toBe("ask")
    expect(JSON.stringify(jevState)).not.toContain("Alice-1987-08-30")
    expect(JSON.stringify(lunaState)).not.toContain("Alice-1987-08-30")

    await hooks["tool.execute.before"](
      { tool: "glob", sessionID: "ses_luna_test", callID: "call_luna_outside" },
      { args: { pattern: "**/*.ts", path: "../outside" } },
    )
    const outside = { status: "allow" }
    await hooks["permission.ask"](
      {
        permission: "glob",
        sessionID: "ses_luna_test",
        patterns: ["**/*.ts"],
        metadata: {
          pattern: "**/*.ts",
          path: "../outside",
          matched_paths: [],
          truncated: false,
          core_trusted_builtin: true,
        },
        tool: { callID: "call_luna_outside" },
      },
      outside,
    )
    expect(outside.status).toBe("ask")

    const untrustedTool = { status: "allow" }
    await hooks["permission.ask"](
      { ...request, metadata: { ...request.metadata, core_trusted_builtin: false } },
      untrustedTool,
    )
    expect(untrustedTool.status).toBe("ask")

    const truncated = { status: "allow" }
    await hooks["permission.ask"]({ ...request, metadata: { ...request.metadata, truncated: true } }, truncated)
    expect(truncated.status).toBe("ask")

    const beforeSensitive = seen.length
    const sensitiveMatch = { status: "allow" }
    await hooks["permission.ask"](
      {
        ...request,
        metadata: { ...request.metadata, matched_paths: [path.join(directory, "patient-123-45-6789.ts")] },
      },
      sensitiveMatch,
    )
    expect(sensitiveMatch.status).toBe("ask")
    expect(seen).toHaveLength(beforeSensitive)
  } finally {
    globalThis.fetch = previousFetch
    if (previousStateHome === undefined) delete process.env.XDG_STATE_HOME
    else process.env.XDG_STATE_HOME = previousStateHome
    if (previousKevSocket === undefined) delete process.env.OPENCODE_KEV_SOCKET
    else process.env.OPENCODE_KEV_SOCKET = previousKevSocket
  }
})
