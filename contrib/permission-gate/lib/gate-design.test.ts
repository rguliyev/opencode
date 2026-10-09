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
  const bash = async (command: string, patterns = [command]) => {
    const output: { status: string; message?: string } = { status: "ask" }
    await ask(
      {
        permission: "bash",
        sessionID: "ses_gate_design",
        patterns,
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
        ["elsewhere", '#!/usr/bin/env bash\nsource "$LIB_FROM_ENV"\n'],
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

test("an installed gate change takes effect on the next request without a restart", () =>
  withEnv(async () => {
    const { cpSync, mkdtempSync, readFileSync, writeFileSync, rmSync, readdirSync } = await import("node:fs")
    const root = mkdtempSync(path.join((await import("node:os")).tmpdir(), "gate-reload-"))
    try {
      cpSync(path.join(import.meta.dir, "../plugins"), path.join(root, "plugins"), { recursive: true })
      cpSync(path.join(import.meta.dir), path.join(root, "lib"), {
        recursive: true,
        filter: (source) => !source.endsWith(".test.ts") && !source.includes(`${path.sep}fixtures`),
      })
      const directory = path.resolve(import.meta.dir, "..")
      globalThis.fetch = (async (input: unknown) => {
        const url = String(input)
        if (url.includes("/session/ses_gate_design/message?"))
          return Response.json([message("msg_gate_design", "user", "Show the git status.")])
        if (url.startsWith("http://gate.test/session/"))
          return Response.json({ id: "ses_gate_design", directory, agent: "solo", title: "gate design" })
        if (url === "https://openrouter.ai/api/alpha/decisions") return new Response("declined", { status: 403 })
        throw new Error(`Unexpected fetch: ${url}`)
      }) as typeof fetch
      const plugin = (await import(path.join(root, "plugins/command-approval.ts"))).default
      const hooks = await plugin({ directory, serverUrl: new URL("http://gate.test") })
      await hooks.provider.models({ models: {} }, { auth: { type: "api", key: "fake-test-key" } })
      const ask = async () => {
        const output: { status: string; message?: string } = { status: "ask" }
        await hooks["permission.ask"](
          { permission: "bash", sessionID: "ses_gate_design", patterns: ["git status --short"], metadata: { command: "git status --short", core_execution_agent: "solo" } },
          output,
        )
        return output
      }
      expect((await ask()).message).not.toBe("reloaded gate")
      const gateFile = path.join(root, "lib/gate.ts")
      const marker = '"permission.ask": async (input: PermissionInput, output: PermissionOutput) => {'
      const source = readFileSync(gateFile, "utf8")
      expect(source).toContain(marker)
      await Bun.sleep(10)
      writeFileSync(gateFile, source.replace(marker, `${marker}\n      output.status = "deny"\n      output.message = "reloaded gate"\n      return`))
      const after = await ask()
      expect(after.status).toBe("deny")
      expect(after.message).toBe("reloaded gate")
      expect(readdirSync(root)).toContain("lib")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  }))

test("a script that sources a file beside it through its own directory is inspected, not refused", () =>
  withEnv(async () => {
    const { mkdtempSync, writeFileSync, rmSync } = await import("node:fs")
    const dir = mkdtempSync(path.join((await import("node:os")).tmpdir(), "gate-srcdir-"))
    try {
      writeFileSync(path.join(dir, "lib.sh"), 'helper() {\n  local line fs_type source dev_id\n  read -r fs_type source dev_id <<<"$1"\n  echo "helper ran"\n}\n')
      writeFileSync(
        path.join(dir, "validate.sh"),
        '#!/usr/bin/env bash\nset -euo pipefail\nDIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)\nreadonly DIR\nsource "$DIR/lib.sh"\nhelper\n',
      )
      writeFileSync(path.join(dir, "inline.sh"), '#!/usr/bin/env bash\nsource "$(dirname "$0")/lib.sh"\nhelper\n')
      writeFileSync(path.join(dir, "reassigned.sh"), '#!/usr/bin/env bash\nDIR=$(dirname "$0")\nDIR=/elsewhere\nsource "$DIR/lib.sh"\n')
      const g = await gate("solo", "Run the validation script.", () => 0.01)
      expect(await g.bash(`bash ${dir}/validate.sh`)).toBe("allow")
      expect(await g.bash(`bash ${dir}/inline.sh`)).toBe("allow")
      expect(await g.bash(`bash ${dir}/reassigned.sh`)).toBe("ask")
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  }))

test("secret metadata, label updates, and empty secret creation reach the reviewers; values and versions stay hard", () =>
  withEnv(async () => {
    const g = await gate("solo", "Set up the tango VPN PSK secret to match staging.", () => 0.01)
    expect(await g.bash("gcloud secrets describe tango-filestore-vpn-psk --project=e2b-tango")).toBe("allow")
    expect(await g.bash("gcloud secrets update tango-filestore-vpn-psk --project=e2b-tango --update-labels=managed_by=terragrunt,tier=tango")).toBe("allow")
    expect(await g.bash("gcloud secrets create tango-filestore-vpn-psk --project=e2b-tango --replication-policy=automatic")).toBe("allow")
    expect(await g.bash("curl -fsS https://secretmanager.googleapis.com/v1/projects/e2b-tango/secrets/tango-filestore-vpn-psk/versions/1")).toBe("allow")
    // Values, new versions, deletes, and other updates stay with the human.
    expect(await g.bash("gcloud secrets create tango-filestore-vpn-psk --project=e2b-tango --data-file=-")).toBe("ask")
    expect(await g.bash("gcloud secrets versions add tango-filestore-vpn-psk --project=e2b-tango --data-file=psk.txt")).toBe("ask")
    expect(await g.bash("gcloud secrets versions access latest --project=e2b-tango --secret=tango-filestore-vpn-psk")).toBe("ask")
    expect(await g.bash("curl -fsS https://secretmanager.googleapis.com/v1/projects/e2b-tango/secrets/tango-filestore-vpn-psk/versions/1:access")).toBe("ask")
    expect(await g.bash("gcloud secrets update tango-filestore-vpn-psk --project=e2b-tango --ttl=1h")).toBe("ask")
    expect(await g.bash("gcloud secrets delete tango-filestore-vpn-psk --project=e2b-tango --quiet")).toBe("ask")
  }))

test("re-reading this OpenCode's own tool output is allowed without review", () =>
  withEnv(async () => {
    const { mkdtempSync, mkdirSync, writeFileSync, rmSync } = await import("node:fs")
    const home = mkdtempSync(path.join((await import("node:os")).tmpdir(), "gate-ochome-"))
    const previous = process.env.OPENCODE_HOME
    let reviewed = 0
    try {
      process.env.OPENCODE_HOME = home
      mkdirSync(path.join(home, "data/tool-output"), { recursive: true })
      const file = path.join(home, "data/tool-output/tool_abc")
      writeFileSync(file, "FAIL node-init swap test\nExpected to equal: 1\n")
      const directory = path.resolve(import.meta.dir, "..")
      globalThis.fetch = (async (input: unknown) => {
        const url = String(input)
        if (url.includes("/session/ses_gate_design/message?"))
          return Response.json([message("msg_gate_design", "user", "Fix the failing chart test.")])
        if (url.startsWith("http://gate.test/session/"))
          return Response.json({ id: "ses_gate_design", directory, agent: "solo", title: "gate design" })
        reviewed += 1
        return new Response("declined", { status: 403 })
      }) as typeof fetch
      const hooks = await (CommandApproval as any)({ directory, serverUrl: new URL("http://gate.test") })
      const output: { status: string } = { status: "ask" }
      await hooks["permission.ask"](
        { permission: "read", sessionID: "ses_gate_design", patterns: [file], metadata: { filepath: file, core_trusted_builtin: true, core_execution_agent: "solo" } },
        output,
      )
      expect(output.status).toBe("allow")
      expect(reviewed).toBe(0)
    } finally {
      if (previous === undefined) delete process.env.OPENCODE_HOME
      else process.env.OPENCODE_HOME = previous
      rmSync(home, { recursive: true, force: true })
    }
  }))

test("a script run after a separate cd is inspected in that directory", () =>
  withEnv(async () => {
    const { mkdtempSync, mkdirSync, writeFileSync, rmSync } = await import("node:fs")
    const dir = mkdtempSync(path.join((await import("node:os")).tmpdir(), "gate-cd-"))
    try {
      mkdirSync(path.join(dir, "scripts"))
      writeFileSync(path.join(dir, "scripts/verify.sh"), '#!/usr/bin/env bash\necho "verified"\n')
      const g = await gate("solo", "Validate the stage 3 worktree.", () => 0.01)
      const output = await g.bash(`cd ${dir} && bash scripts/verify.sh`, [`cd ${dir}`, "bash scripts/verify.sh"])
      expect(output).toBe("allow")
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  }))
