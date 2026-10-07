import { afterAll, beforeAll, expect, test } from "bun:test"
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"
import CommandApproval from "../plugins/command-approval"
import { classifyPath, classifyProject, loadEnvironmentPolicy } from "./environment-policy"

const directory = path.resolve(import.meta.dir, "..")
const session = "ses_reviewer_policy_test"

type Review = { system: string; state: Record<string, unknown> }

// One gate with recording reviewers. Jev denies with low confidence unless
// told otherwise, so every request reaches the final reviewer, whose choice
// the test sets.
const harness = {
  finalChoice: "allow" as "allow" | "ask",
  jevAllow: false,
  human: "Investigate the staging incident and clean up the scratch cache.",
  jev: [] as Record<string, unknown>[],
  final: [] as Review[],
  hooks: undefined as any,
}
const previous = {
  fetch: globalThis.fetch,
  stateHome: process.env.XDG_STATE_HOME,
  kev: process.env.OPENCODE_KEV_SOCKET,
}

beforeAll(async () => {
  process.env.XDG_STATE_HOME = "/dev/null"
  process.env.OPENCODE_KEV_SOCKET = "/dev/null/no-kev-socket"
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input instanceof Request ? input.url : input)
    if (url.includes(`/session/${session}/message?`))
      return Response.json([
        { info: { id: "msg_policy_human", role: "user", time: { created: 1_000 } }, parts: [{ type: "text", text: harness.human }] },
      ])
    if (url.startsWith("http://gate.test/session/"))
      return Response.json({ id: session, directory, agent: "solo", title: "Policy test" })
    if (url === "https://openrouter.ai/api/alpha/decisions") {
      const payload = JSON.parse(String(init?.body))
      harness.jev.push(payload)
      const answers: Record<string, unknown> = {
        verdict: harness.jevAllow
          ? { type: "choice", choice: "allow", confidence: 0.95, probabilities: { allow: 0.95, deny: 0.05 } }
          : { type: "choice", choice: "deny", confidence: 0.3, probabilities: { allow: 0.4, deny: 0.6 } },
      }
      for (const id of Object.keys(payload.questions)) if (id !== "verdict") answers[id] = { type: "noul", noul: 0.01 }
      return Response.json({ model: "typesafe/jev-1.13", answers })
    }
    throw new Error(`Unexpected fetch: ${url}`)
  }) as typeof fetch
  harness.hooks = await (CommandApproval as any)({
    directory,
    serverUrl: new URL("http://gate.test"),
    reviewPermission: async (input: { system: string; state: string }) => {
      // Core rejects larger review input before calling the model.
      if (input.system.length > 8_000 || input.state.length > 128_000) throw new Error("over budget")
      harness.final.push({ system: input.system, state: JSON.parse(input.state) })
      return { model: "google/gemini-3.8-flash", choice: harness.finalChoice, reason: "Judged against the policy." }
    },
  })
  const ask = harness.hooks["permission.ask"]
  harness.hooks["permission.ask"] = (input: { metadata?: Record<string, unknown> }, output: unknown) =>
    ask({ ...input, metadata: { ...input.metadata, core_execution_agent: "solo" } }, output)
  await harness.hooks.provider.models({ models: {} }, { auth: { type: "api", key: "fake-test-key" } })
})

afterAll(() => {
  globalThis.fetch = previous.fetch
  if (previous.stateHome === undefined) delete process.env.XDG_STATE_HOME
  else process.env.XDG_STATE_HOME = previous.stateHome
  if (previous.kev === undefined) delete process.env.OPENCODE_KEV_SOCKET
  else process.env.OPENCODE_KEV_SOCKET = previous.kev
})

async function bash(command: string, options: { patterns?: string[]; workdir?: string } = {}) {
  harness.jev = []
  harness.final = []
  const callID = `call_${Math.random().toString(36).slice(2)}`
  if (options.workdir)
    await harness.hooks["tool.execute.before"](
      { tool: "bash", sessionID: session, callID },
      { args: { command, workdir: options.workdir } },
    )
  const output = { status: "ask", message: "" }
  await harness.hooks["permission.ask"](
    {
      permission: "bash",
      sessionID: session,
      patterns: options.patterns ?? [command],
      metadata: { command },
      tool: { callID },
    },
    output,
  )
  return output
}

async function action(
  permission: string,
  patterns: string[],
  metadata: Record<string, unknown>,
  call?: { tool: string; args: unknown },
) {
  harness.jev = []
  harness.final = []
  const callID = `call_${Math.random().toString(36).slice(2)}`
  if (call) await harness.hooks["tool.execute.before"]({ tool: call.tool, sessionID: session, callID }, { args: call.args })
  const output = { status: "ask", message: "" }
  await harness.hooks["permission.ask"]({ permission, sessionID: session, patterns, metadata, tool: { callID } }, output)
  return output
}

const context = (state: Record<string, unknown> | undefined) => (state?.context ?? {}) as Record<string, any>

test("the shipped policy file loads and classifies every allowlisted project", () => {
  const policy = loadEnvironmentPolicy()
  expect(policy).toBeDefined()
  expect(classifyProject(policy!, "e2b-dev-rauf-guliyev")).toBe("dev")
  expect(classifyProject(policy!, "e2b-staging")).toBe("staging")
  expect(classifyProject(policy!, "e2b-staging-jirka")).toBe("staging")
  expect(classifyProject(policy!, "e2b-byoc-staging")).toBe("staging")
  for (const project of ["e2b-foxtrot", "e2b-tango", "e2b-juliett-europe", "sandboxes-prod-5783", "prj-e2b-cell-0002", "felix-sandboxes-prod-c1ab"])
    expect(classifyProject(policy!, project)).toBe("production")
  for (const project of ["e2b-shared", "e2b-management", "e2b-global", "e2b-global-dbt", "e2b-artifacts", "e2b-observability"])
    expect(classifyProject(policy!, project)).toBe("shared")
  expect(classifyProject(policy!, "e2b-growth")).toBe("unclassified")
  expect(classifyPath(policy!, "/data/rguliyev/tmp/opencode/worktrees/charts/x.yaml")).toBe("worktree")
  expect(classifyPath(policy!, "/data/rguliyev/tmp/opencode/gate-delegation-runtime/run.sh")).toBe("gate_runtime")
  expect(classifyPath(policy!, "/data/rguliyev/tmp/opencode/audit/notes.md")).toBe("scratch")
  expect(classifyPath(policy!, "/data/rguliyev/tmp/opencode-other/x")).toBe("other")
  expect(classifyPath(policy!, "/data/rguliyev/src/infra/main.tf")).toBe("other")
})

test("a malformed or missing policy file loads as unavailable", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "environment-policy-"))
  try {
    const file = path.join(dir, "policy.json")
    const valid = JSON.parse(readFileSync(new URL("./environment-policy.json", import.meta.url), "utf8"))
    writeFileSync(file, JSON.stringify(valid))
    expect(loadEnvironmentPolicy(file)).toBeDefined()
    writeFileSync(file, JSON.stringify({ ...valid, local_paths: { ...valid.local_paths, classes: [{ class: "x", prefix: "relative", policy: "p" }] } }))
    expect(loadEnvironmentPolicy(file)).toBeUndefined()
    writeFileSync(file, "{")
    expect(loadEnvironmentPolicy(file)).toBeUndefined()
    expect(loadEnvironmentPolicy(path.join(dir, "missing.json"))).toBeUndefined()
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test("both reviewers receive the environment policy and this request's classification", async () => {
  const output = await bash("gcloud compute instances list --project=e2b-foxtrot --format=json")
  expect(output.status).toBe("allow")
  for (const state of [harness.jev[0]?.state as Record<string, unknown>, harness.final[0]?.state]) {
    expect(context(state).environment_policy?.gcp_projects?.classes?.map((item: { class: string }) => item.class)).toEqual([
      "dev",
      "staging",
      "production",
      "shared",
    ])
    expect(context(state).environment?.gcp_projects).toEqual([{ project: "e2b-foxtrot", class: "production" }])
  }
  expect(JSON.stringify((harness.jev[0]?.questions as Record<string, unknown>)?.verdict)).toContain(
    "context.environment_policy is the human's trusted standing policy",
  )
  const system = harness.final[0]!.system
  expect(system.length).toBeLessThanOrEqual(8_000)
  expect(system).toContain("context.environment_policy is the human's standing policy")

  // Action paths are classified too.
  const file = "/data/rguliyev/tmp/opencode/policy-test-scratch/notes.md"
  await action("edit", [file.slice(1)], { filepath: file, diff: "+notes" }, { tool: "edit", args: { filePath: file } })
  expect(context(harness.final[0]?.state).environment?.paths).toContainEqual({ path: file, class: "scratch" })
})

// Asserts the request reached both reviewers with the finding, was allowed on
// the final reviewer's allow, and asks when the final reviewer asks.
async function expectEvidence(run: () => Promise<{ status: string; message?: string }>, finding: string, detail?: string) {
  harness.finalChoice = "allow"
  const allowed = await run()
  expect(allowed.status).toBe("allow")
  for (const state of [harness.jev.at(-1)?.state as Record<string, unknown>, harness.final.at(-1)?.state]) {
    const items = (context(state).gate_evidence ?? []) as { finding: string; detail: string }[]
    expect(items.map((item) => item.finding)).toContain(finding)
    if (detail) expect(items.map((item) => item.detail).join("\n")).toContain(detail)
    expect(context(state).environment_policy?.finding_guidance?.[finding]).toBeString()
  }
  harness.finalChoice = "ask"
  try {
    expect((await run()).status).toBe("ask")
  } finally {
    harness.finalChoice = "allow"
  }
}

async function expectHard(run: () => Promise<{ status: string; message?: string }>, reason?: string) {
  harness.finalChoice = "allow"
  harness.jevAllow = true
  try {
    const output = await run()
    expect(output.status).toBe("ask")
    if (reason) expect(output.message).toContain(reason)
  } finally {
    harness.jevAllow = false
  }
}

test("generic credential-like patterns are reviewer evidence; credential material stays a human gate", async () => {
  const dir = mkdtempSync("/data/rguliyev/tmp/opencode/reviewer-policy-test-")
  try {
    // Secret names, go-getter sources, and pagination fields trip the
    // generic detectors; reviewers see the redacted text and decide.
    await expectEvidence(
      () => bash(`curl -s -u deploy:hunter22pass https://registry.example.test/v2/_catalog`),
      "credential_pattern",
      "credential-like literal in command",
    )
    await expectEvidence(
      () => bash(`terraform init -backend-config="password=correcthorse99"`),
      "credential_pattern",
    )
    const compose = path.join(dir, "compose.yaml")
    writeFileSync(compose, "services:\n  db:\n    environment:\n      DATABASE_URL: postgres://app:localdevpass@db:5432/app\n")
    await expectEvidence(
      () => action("read", [compose], { filepath: compose }, { tool: "read", args: { filePath: compose } }),
      "credential_pattern",
      "credential-like literal in read target",
    )
    const script = path.join(dir, "sweep.py")
    writeFileSync(script, 'API = "https://api.example.test"\nheaders = {"api_key": "placeholder-value-123"}\nprint(API)\n')
    await expectEvidence(() => bash(`python3 ${script}`), "credential_pattern", "credential-like literal in inspected script")

    // Provider-format tokens, private keys, and webhook URLs are credential material.
    const token = "ghp_" + "Q".repeat(36)
    await expectHard(() => bash(`curl -H "Authorization: token ${token}" https://api.github.com/user`), "It reads, uses, or contains a secret")
    const keyFile = path.join(dir, "deploy-notes.txt")
    writeFileSync(keyFile, "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")
    await expectHard(() => action("read", [keyFile], { filepath: keyFile }, { tool: "read", args: { filePath: keyFile } }))
    const tokenScript = path.join(dir, "push.sh")
    writeFileSync(tokenScript, `#!/usr/bin/env bash\nexport GH_TOKEN=${token}\ngh pr list\n`)
    await expectHard(() => bash(`bash ${tokenScript}`))
    await expectHard(() =>
      action("edit", ["README.md"], { filepath: "README.md", diff: `+webhook: https://hooks.slack.com/services/T000/B000/${"x".repeat(24)}` }),
    )
    // Secret values and token minting stay hard.
    await expectHard(() => bash("gcloud secrets versions access latest --secret=grafana-token --project=e2b-staging"))
    await expectHard(() => bash("echo $(gcloud auth print-access-token)"))
    await expectHard(() => bash("gcloud auth print-access-token"))
    await expectHard(() => bash("gcloud auth print-access-token; gcloud auth print-access-token", { patterns: ["gcloud auth print-access-token"] }))
    // An action whose review copy cannot be redacted is withheld and asks.
    await expectHard(() => action("tool_call", ["custom_tool"], { tool: "custom_tool", ["token=" + "k".repeat(20)]: 1 }))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test("ambient credential use is reviewer evidence; credential stores stay a human gate", async () => {
  await expectEvidence(
    () => bash(`python3 -c 'from google.cloud import bigquery; print(list(bigquery.Client(project="e2b-staging").query("select 1").result()))'`),
    "ambient_credentials",
  )
  await expectEvidence(
    () => bash(`curl -s -H "Authorization: Bearer $GRAFANA_TOKEN" https://e2bstg.grafana.net/api/health`),
    "ambient_credentials",
  )
  const home = (await import("node:os")).homedir()
  await expectHard(() => bash(`cat ${home}/.ssh/config`), "a secret")
  await expectHard(() => bash("ssh-keygen -y -f ~/.ssh/id_ed25519"))
  await expectHard(() => bash("cat ~/.aws/credentials"))
  await expectHard(() => bash("jq -r .refresh_token ~/.config/gcloud/application_default_credentials.json"))
  const sshConfig = path.join(home, ".ssh", "config")
  await expectHard(() => action("read", [sshConfig], { filepath: sshConfig }, { tool: "read", args: { filePath: sshConfig } }), "credential store")
  await expectHard(() =>
    action("edit", [path.join(home, ".ssh/authorized_keys").slice(1)], { filepath: path.join(home, ".ssh/authorized_keys"), diff: "+ssh-ed25519 AAAA" }),
  )
  await expectHard(() =>
    action("grep", ["password"], { pattern: "password", path: home, requested_path: home, core_trusted_builtin: true }, { tool: "grep", args: { pattern: "password", path: home } }),
  )
  await expectHard(() =>
    action(
      "external_directory",
      [path.join(home, ".ssh", "*")],
      { filepath: sshConfig, resolved_filepath: sshConfig, parentDir: path.dirname(sshConfig), core_trusted_builtin: true },
      { tool: "read", args: { filePath: sshConfig } },
    ),
  )
  const dir = mkdtempSync("/data/rguliyev/tmp/opencode/reviewer-policy-env-")
  try {
    const dotenv = path.join(dir, ".env")
    writeFileSync(dotenv, "PORT=8080\n")
    await expectHard(() => action("read", [dotenv], { filepath: dotenv }, { tool: "read", args: { filePath: dotenv } }))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test("a dynamically chosen GCP project is reviewer evidence; credential switches and unlisted projects stay hard", async () => {
  // Real prompts: Python code passing a quoted --project flag, and a loop variable.
  const code = `python3 -c 'import subprocess; print(subprocess.run(["gcloud", "logging", "read", "severity>=ERROR", "--project=e2b-staging", "--limit=5"], capture_output=True).stdout)'`
  await expectEvidence(() => bash(code), "gcp_dynamic_project", "GCP project chosen dynamically")
  expect(context(harness.final.at(-1)?.state).environment?.gcp_projects).toContainEqual({ project: "e2b-staging", class: "staging" })
  await expectEvidence(
    () => bash('for proj in $(cat projects.txt); do gcloud run services list --project="$proj"; done', {
      patterns: ['gcloud run services list --project="$proj"'],
    }),
    "gcp_dynamic_project",
  )
  // A loop over listed projects resolves statically: no finding at all.
  harness.jevAllow = true
  try {
    expect(
      (
        await bash('for p in e2b-staging e2b-foxtrot; do gcloud container clusters list --project="$p"; done', {
          patterns: ['gcloud container clusters list --project="$p"'],
        })
      ).status,
    ).toBe("allow")
    expect(harness.final).toHaveLength(0)
  } finally {
    harness.jevAllow = false
  }
  await expectHard(() => bash("gcloud compute instances list --account=other@example.test"), "Google Cloud login")
  await expectHard(() => bash("gcloud compute instances list --impersonate-service-account=sa@e2b-staging.iam.gserviceaccount.com"))
  await expectHard(() => bash("CLOUDSDK_CONFIG=/tmp/other gcloud projects list"))
  await expectHard(() => bash("gcloud auth activate-service-account --key-file=/tmp/key.json"))
  await expectHard(() => bash("gcloud compute instances list --project=some-unlisted-project"), "some-unlisted-project")
})
