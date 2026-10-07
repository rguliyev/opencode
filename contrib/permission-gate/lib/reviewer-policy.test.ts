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
