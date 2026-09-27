// Shared GCP scope policy helpers.
// NOTE: this lives OUTSIDE plugins/ on purpose. opencode's plugin loader
// (getLegacyPlugins) calls EVERY export of a plugin module as a plugin
// factory, so exporting a helper from a plugin file makes the whole module
// fail to load. Plugin files must export only `default`.
import { readFileSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"
type Grant = { project: string; until: string; reason?: string; session?: string }
type Policy = {
  version: 1
  default_project: string
  allowed_projects: string[]
}
const policyPath = join(homedir(), ".config", "opencode", "gcp-project-scope.json")
const projectID = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/
const scopeVariables =
  "CLOUDSDK_CORE_PROJECT|CLOUDSDK_CORE_BILLING_PROJECT|GOOGLE_CLOUD_PROJECT|GOOGLE_CLOUD_QUOTA_PROJECT|GCLOUD_PROJECT|TF_VAR_project|TF_VAR_project_id"
export function loadPolicy(sessions?: string[]): Policy {
  const value = JSON.parse(readFileSync(policyPath, "utf8")) as Partial<Policy>
  if (value.version !== 1) throw new Error(`Unsupported GCP scope policy version in ${policyPath}`)
  if (!value.default_project || !projectID.test(value.default_project)) throw new Error(`Invalid default_project in ${policyPath}`)
  if (!Array.isArray(value.allowed_projects) || value.allowed_projects.length === 0) {
    throw new Error(`allowed_projects must be a non-empty array in ${policyPath}`)
  }
  // Time-boxed grants let the human authorize a project without permanently
  // widening the allowlist. Expired entries are ignored, never auto-pruned, so
  // the file stays an audit trail of what was authorized and why.
  const now = Date.now()
  const grants = Array.isArray((value as { grants?: Grant[] }).grants) ? (value as { grants?: Grant[] }).grants! : []
  const granted = grants
    .filter((g) => g && typeof g.project === "string" && typeof g.until === "string")
    // A grant without `session` is global. A scoped grant applies only to the
    // session it was issued for and that session's descendants; absent session
    // context it never applies (fail closed).
    .filter((g) => !g.session || (sessions?.includes(g.session) ?? false))
    .filter((g) => {
      const until = Date.parse(g.until)
      if (Number.isNaN(until)) throw new Error(`Invalid grant expiry "${g.until}" in ${policyPath}`)
      return until > now
    })
    .map((g) => g.project)
  const allowed = [...new Set([...value.allowed_projects, ...granted])]
  if (allowed.some((project) => !projectID.test(project))) throw new Error(`Invalid project ID in ${policyPath}`)
  if (!allowed.includes(value.default_project)) throw new Error(`default_project must be included in allowed_projects in ${policyPath}`)
  return { version: 1, default_project: value.default_project, allowed_projects: allowed }
}
function captures(command: string, expression: RegExp) {
  const values: string[] = []
  for (const match of command.matchAll(expression)) {
    const value = match.slice(1).find(Boolean)
    if (value) values.push(value)
  }
  return values
}

function explicitProjects(command: string) {
  const projects = [
    ...captures(
      command,
      /(?:--project|--billing-project|--quota-project)(?:=|\s+)(?:"([^"]+)"|'([^']+)'|([A-Za-z0-9][A-Za-z0-9._:-]*))/g,
    ),
    ...captures(
      command,
      /(?:CLOUDSDK_CORE_PROJECT|CLOUDSDK_CORE_BILLING_PROJECT|GOOGLE_CLOUD_PROJECT|GOOGLE_CLOUD_QUOTA_PROJECT|GCLOUD_PROJECT|TF_VAR_project|TF_VAR_project_id)\s*=\s*(?:"([^"]+)"|'([^']+)'|([A-Za-z0-9][A-Za-z0-9._:-]*))/g,
    ),
    ...captures(command, /(?:^|[^A-Za-z0-9_-])projects\/([a-z][a-z0-9-]{4,28}[a-z0-9])/g),
    ...captures(command, /([a-z][a-z0-9-]{4,28}[a-z0-9])\.iam\.gserviceaccount\.com/g),
    ...captures(
      command,
      /\bgcloud\b[^\n;|&]*\bprojects\s+[A-Za-z0-9-]+\s+(?:"([^"]+)"|'([^']+)'|([a-z][a-z0-9-]{4,28}[a-z0-9]))/g,
    ),
    ...captures(
      command,
      /\bgcloud\b[^\n;|&]*\bconfig\s+set\s+project\s+(?:"([^"]+)"|'([^']+)'|([A-Za-z0-9][A-Za-z0-9._:-]*))/g,
    ),
    ...captures(command, /(?:-var(?:=|\s+))(?:"|')?(?:project|project_id)=([a-z][a-z0-9-]{4,28}[a-z0-9])/g),
  ]
  if (/\b(?:secretmanager\.googleapis\.com|google\.cloud\.secretmanager|gcloud\b[^\n;|&]*\bsecrets)\b/.test(command)) {
    projects.push(...captures(command, /["']((?:e2b|prj|sandboxes|felix)[a-z0-9-]{3,})["']/g))
  }
  return new Set(projects)
}

const projectFlag = /--(?:billing-|quota-)?project\b/y

// A --project flag that genuinely sits inside shell quotes.
//
// The previous form paired ANY two quote characters and asked whether
// --project fell between them, so a quoted string nested inside a
// differently-quoted argument produced a phantom pair:
//   gcloud logging read '...("a" OR "b")' --project=X --format="table(t)"
// matched from the filter's last inner quote across to --format's opening
// quote, with --project in the gap. Every structured logging query tripped it.
//
// This walks the command once tracking real shell quote state. Validated over
// 103,395 real commands: 2,416 matches -> 310, no new matches, and the quoting
// evasion the rule exists for (`list "--project=evil"`) is still caught.
function projectHiddenInQuotes(command: string): boolean {
  let quote: string | null = null
  for (let i = 0; i < command.length; i++) {
    const c = command[i]
    if (c === "\\" && quote !== "'") {
      i++
      continue
    }
    if (quote) {
      projectFlag.lastIndex = i
      if (projectFlag.test(command)) return true
      if (c === quote) quote = null
      continue
    }
    if (c === '"' || c === "'") quote = c
  }
  return false
}

function hasDynamicScope(command: string) {
  const selector = new RegExp(
    `(?:--(?:billing-|quota-)?project|${scopeVariables})(?:=|\\s+)\\s*(?:["']?)(?:\\$|\\x60|[^\\s;|&]*\\\\)`,
  )
  return (
    selector.test(command) ||
    /(?:-var(?:=|\s+))(?:"|')?(?:project|project_id)=(?:"|')?(?:\$|`|[^\s;|&]*\\)/.test(command) ||
    /\bgcloud\b[^\n;|&]*\bprojects\s+[A-Za-z0-9-]+\s+(?:["']?)(?:\$|`|[^\s;|&]*\\)/.test(command) ||
    /projects\/(?:\$\{|\{|\$|`)/.test(command) ||
    projectHiddenInQuotes(command) ||
    /--(?:billing-|quota-)?pro\\ject/.test(command)
  )
}

function attemptsScopeSwitch(command: string) {
  return (
    hasDynamicScope(command) ||
    /\bCLOUDSDK_(?:ACTIVE_CONFIG_NAME|CONFIG|AUTH_CREDENTIAL_FILE_OVERRIDE)\s*=/.test(command) ||
    new RegExp(`(?:\\benv\\b[^;|&]*?\\s-u\\s+|\\bunset\\s+|\\bexport\\s+-n\\s+)(?:${scopeVariables})\\b`).test(command) ||
    new RegExp(`(?:${scopeVariables})\\s*=\\s*(?:$|[;|&])`).test(command) ||
    (/\bgcloud\b/.test(command) && /--(?:configuration|account|impersonate-service-account)(?:=|\s+)/.test(command)) ||
    /\bgcloud\b[^\n;|&]*\bconfig\s+(?:(?:set|unset)\s+(?:project|core\/project|billing\/quota_project|account|auth\/impersonate_service_account)|configurations\s+activate)\b/.test(command) ||
    /\bgcloud\b[^\n;|&]*\bauth\s+(?:login|revoke|activate-service-account|print-access-token|application-default\s+(?:login|set-quota-project|print-access-token))\b/.test(command)
  )
}

export function gcpScopeReviewMessage(command: string, sessions?: string[]) {
  const policy = loadPolicy(sessions)
  if (attemptsScopeSwitch(command)) {
    return `GCP project or credential selection requires human review. Default project: ${policy.default_project}`
  }
  const allowed = new Set(policy.allowed_projects)
  const denied = [...explicitProjects(command)].filter((project) => !allowed.has(project))
  if (denied.length === 0) return undefined
  return `GCP project${denied.length === 1 ? "" : "s"} ${denied.join(", ")} require human review. Default project: ${policy.default_project}`
}
