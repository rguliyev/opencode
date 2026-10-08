import { expect, test } from "bun:test"
import path from "node:path"
import { homedir } from "node:os"
import CommandApproval from "../plugins/command-approval"

// The final reviewer decides from the human's context; Jev's mutation score
// and the hard rules only override it where a mutation or secret is certain.

function message(id: string, role: "user" | "assistant", text: string) {
  return {
    info: { id, role, sessionID: "ses_gate_design", time: { created: 1 } },
    parts: [{ id: `${id}_part`, type: "text", text }],
  }
}

async function gate(agent: string, human: string, jevMutation: (command: string | undefined) => number) {
  const directory = path.resolve(import.meta.dir, "..")
  let finalChoice = "allow"
  globalThis.fetch = (async (input: unknown, init?: RequestInit) => {
    const url = String(input)
    if (url.includes("/session/ses_gate_design/message?"))
      return Response.json([message("msg_gate_design", "user", human)])
    if (url.startsWith("http://gate.test/session/"))
      return Response.json({ id: "ses_gate_design", directory, agent, title: "gate design" })
    if (url === "https://openrouter.ai/api/alpha/decisions") {
      const payload = JSON.parse(String(init?.body))
      const answers: Record<string, unknown> = {
        verdict: { type: "choice", choice: "allow", confidence: 0.6, probabilities: { allow: 0.6, deny: 0.4 } },
      }
      for (const id of Object.keys(payload.questions))
        if (id !== "verdict")
          answers[id] = { type: "noul", noul: id === "reviewer_mutation" ? jevMutation(payload.state.command) : 0.01 }
      return Response.json({ model: "typesafe/jev-1.13", answers })
    }
    throw new Error(`Unexpected fetch: ${url}`)
  }) as typeof fetch
  const hooks = await (CommandApproval as any)({
    directory,
    serverUrl: new URL("http://gate.test"),
    reviewPermission: async () => ({ model: "google/gemini-3.8-flash", choice: finalChoice, reason: "Judged from context." }),
  })
  const ask = hooks["permission.ask"]
  await hooks.provider.models({ models: {} }, { auth: { type: "api", key: "fake-test-key" } })
  const bash = async (command: string) => {
    const output: { status: string; message?: string } = { status: "ask" }
    await ask(
      {
        permission: "bash",
        sessionID: "ses_gate_design",
        patterns: [command],
        metadata: { command, purpose: "Carry out the human's request", core_execution_agent: agent },
      },
      output,
    )
    if (process.env.GATE_DESIGN_DEBUG) console.log(command, output.status, output.message)
    return output.status
  }
  return { bash, setFinal: (choice: string) => (finalChoice = choice) }
}

async function withEnv<T>(run: () => Promise<T>) {
  const previousFetch = globalThis.fetch
  const previousStateHome = process.env.XDG_STATE_HOME
  const previousKevSocket = process.env.OPENCODE_KEV_SOCKET
  process.env.XDG_STATE_HOME = "/dev/null"
  process.env.OPENCODE_KEV_SOCKET = "/dev/null/no-kev-socket"
  try {
    return await run()
  } finally {
    globalThis.fetch = previousFetch
    if (previousStateHome === undefined) delete process.env.XDG_STATE_HOME
    else process.env.XDG_STATE_HOME = previousStateHome
    if (previousKevSocket === undefined) delete process.env.OPENCODE_KEV_SOCKET
    else process.env.OPENCODE_KEV_SOCKET = previousKevSocket
  }
}

test("a lease-pinned force push of the requested feature branch is the final reviewer's call", () =>
  withEnv(async () => {
    const sha = "a".repeat(40)
    const g = await gate("solo", "Rebase the branch onto main and push it to update the PR.", () => 0.01)
    expect(await g.bash(`git push --force-with-lease=refs/heads/staging-filestore-retirement:${sha} origin HEAD:refs/heads/staging-filestore-retirement`)).toBe("allow")
    // An unpinned lease, a bare force, a lease on another branch, or a shared branch stays with the human.
    expect(await g.bash("git push --force-with-lease origin HEAD:refs/heads/staging-filestore-retirement")).toBe("ask")
    expect(await g.bash("git push --force origin HEAD:refs/heads/staging-filestore-retirement")).toBe("ask")
    expect(await g.bash(`git push --force-with-lease=refs/heads/other:${sha} origin HEAD:refs/heads/staging-filestore-retirement`)).toBe("ask")
    expect(await g.bash(`git push --force-with-lease=refs/heads/main:${sha} origin HEAD:refs/heads/main`)).toBe("ask")
    g.setFinal("ask")
    expect(await g.bash(`git push --force-with-lease=refs/heads/staging-filestore-retirement:${sha} origin HEAD:refs/heads/staging-filestore-retirement`)).toBe("ask")
  }))

test("Jev's uncertain mutation score defers to the final reviewer for a read-only agent; a confident one does not", () =>
  withEnv(async () => {
    const scores: Record<string, number> = {
      "git status --short": 0.4,
      "python3 -m json.tool --indent 2": 0.79,
      "python3 -m json.tool in.json out.json": 0.95,
    }
    const g = await gate("deep-reviewer", "Review the current branch.", (command) => scores[command ?? ""] ?? 0.01)
    expect(await g.bash("git status --short")).toBe("allow")
    expect(await g.bash("python3 -m json.tool --indent 2")).toBe("allow")
    expect(await g.bash("python3 -m json.tool in.json out.json")).toBe("ask")
  }))

test("host-key lookups and gcloud compute ssh with the GCE key reach the reviewers; private keys stay hard", () =>
  withEnv(async () => {
    const home = homedir()
    const g = await gate("solo", "Connect to the prod node and inspect the XFS settings; don't alter anything.", () => 0.01)
    expect(await g.bash(`ssh-keygen -F 10.138.1.54 -f ${home}/.ssh/known_hosts`)).toBe("allow")
    expect(
      await g.bash(
        `gcloud compute ssh orch-client-orchestrator-n2-m4d6 --project=e2b-foxtrot --zone=us-west1-c --tunnel-through-iap --ssh-key-file=${home}/.ssh/google_compute_engine --command='xfs_info /orchestrator'`,
      ),
    ).toBe("allow")
    expect(await g.bash(`cat ${home}/.ssh/google_compute_engine`)).toBe("ask")
    expect(await g.bash(`cat ${home}/.ssh/id_ed25519`)).toBe("ask")
    expect(await g.bash(`cat ${home}/.ssh/config`)).toBe("ask")
  }))

test("a YAML read target's manifest kinds reach the reviewers", () =>
  withEnv(async () => {
    const directory = path.resolve(import.meta.dir, "..")
    const file = path.join(import.meta.dir, "fixtures/secrets/orchestrator.yaml")
    let state: Record<string, unknown> | undefined
    globalThis.fetch = (async (input: unknown, init?: RequestInit) => {
      const url = String(input)
      if (url.includes("/session/ses_gate_design/message?"))
        return Response.json([message("msg_gate_design", "user", "Map the staging secrets wiring.")])
      if (url.startsWith("http://gate.test/session/"))
        return Response.json({ id: "ses_gate_design", directory, agent: "solo", title: "gate design" })
      if (url === "https://openrouter.ai/api/alpha/decisions") {
        state = JSON.parse(String(init?.body)).state
        return new Response("declined", { status: 403 })
      }
      throw new Error(`Unexpected fetch: ${url}`)
    }) as typeof fetch
    const hooks = await (CommandApproval as any)({ directory, serverUrl: new URL("http://gate.test") })
    await hooks.provider.models({ models: {} }, { auth: { type: "api", key: "fake-test-key" } })
    await hooks["permission.ask"](
      {
        permission: "read",
        sessionID: "ses_gate_design",
        patterns: [file],
        metadata: { filepath: file, core_trusted_builtin: true, core_execution_agent: "solo" },
      },
      { status: "ask" },
    )
    expect(JSON.stringify(state)).toContain('"manifest_kinds":["ExternalSecret"]')
  }))

test("scripts named through $TMPDIR or a literal path variable reach the reviewers", () =>
  withEnv(async () => {
    const directory = path.resolve(import.meta.dir, "..")
    const fixtures = path.join(import.meta.dir, "fixtures/vars")
    const previousTmp = process.env.TMPDIR
    let state: Record<string, unknown> | undefined
    globalThis.fetch = (async (input: unknown, init?: RequestInit) => {
      const url = String(input)
      if (url.includes("/session/ses_gate_design/message?"))
        return Response.json([message("msg_gate_design", "user", "Run the extracted chart tests.")])
      if (url.startsWith("http://gate.test/session/"))
        return Response.json({ id: "ses_gate_design", directory, agent: "solo", title: "gate design" })
      if (url === "https://openrouter.ai/api/alpha/decisions") {
        state = JSON.parse(String(init?.body)).state
        return new Response("declined", { status: 403 })
      }
      throw new Error(`Unexpected fetch: ${url}`)
    }) as typeof fetch
    const hooks = await (CommandApproval as any)({ directory, serverUrl: new URL("http://gate.test") })
    await hooks.provider.models({ models: {} }, { auth: { type: "api", key: "fake-test-key" } })
    const run = async (patterns: string[]) => {
      state = undefined
      await hooks["permission.ask"](
        {
          permission: "bash",
          sessionID: "ses_gate_design",
          patterns,
          metadata: { command: patterns.join("\n"), core_execution_agent: "solo" },
        },
        { status: "ask" },
      )
      return JSON.stringify(state)
    }
    try {
      process.env.TMPDIR = path.dirname(fixtures)
      expect(await run(['bash "$TMPDIR/vars/check.sh"'])).toContain("fixture check ran")
      expect(await run([`D=${fixtures}`, 'bash "$D/check.sh"'])).toContain("fixture check ran")
      // Reassigned or loop-bound variables stay unresolved.
      expect(await run([`D=${fixtures}`, "D=/nonexistent", 'bash "$D/check.sh"'])).not.toContain("fixture check ran")
      expect(await run([`D=${fixtures}`, "for D in /a /b; do :; done", 'bash "$D/check.sh"'])).not.toContain("fixture check ran")
    } finally {
      if (previousTmp === undefined) delete process.env.TMPDIR
      else process.env.TMPDIR = previousTmp
    }
  }))

test("a version manager's dispatcher is judged as the tool it runs, not as an uninspectable script", () =>
  withEnv(async () => {
    const { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync } = await import("node:fs")
    const home = mkdtempSync(path.join((await import("node:os")).tmpdir(), "gate-home-"))
    const previousHome = process.env.HOME
    try {
      for (const [dir, body] of [
        [".tfenv/bin", '#!/usr/bin/env bash\nsource "$(dirname "$0")/../lib/helpers.sh"\nexec terraform-real "$@"\n'],
        ["elsewhere", '#!/usr/bin/env bash\nsource "$(dirname "$0")/lib.sh"\n'],
      ] as const) {
        mkdirSync(path.join(home, dir), { recursive: true })
        writeFileSync(path.join(home, dir, "terraform"), body)
        chmodSync(path.join(home, dir, "terraform"), 0o755)
      }
      process.env.HOME = home
      const g = await gate("solo", "Check the terraform version.", () => 0.01)
      expect(await g.bash(`${home}/.tfenv/bin/terraform version`)).toBe("allow")
      expect(await g.bash(`${home}/elsewhere/terraform version`)).toBe("ask")
    } finally {
      if (previousHome === undefined) delete process.env.HOME
      else process.env.HOME = previousHome
      rmSync(home, { recursive: true, force: true })
    }
  }))

test("operation words inside inline Python that cannot start a process are text, not operations", () =>
  withEnv(async () => {
    const g = await gate("solo", "Check whether the startup script still has the wipefs guard.", () => 0.01)
    const reads = `python3 -c "\nimport re\ntext = open('charts/node-init/files/local-ssd-startup.sh').read()\nprint(bool(re.search(r'signatures=\\$\\(wipefs --no-act', text)))\n"`
    expect(await g.bash(reads)).toBe("allow")
    const spawns = `python3 -c "\nimport subprocess\nsubprocess.run(['sh', '-c', 'x=\\$(wipefs -a /dev/sdb)'])\n"`
    expect(await g.bash(spawns)).toBe("ask")
  }))
