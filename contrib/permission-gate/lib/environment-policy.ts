// Loads the human-edited reviewer policy (environment-policy.json) and
// classifies GCP projects and local paths against it. Lives OUTSIDE plugins/
// because opencode's plugin loader calls every export of a plugin module as a
// plugin factory.
import { readFileSync, statSync } from "node:fs"
import path from "node:path"

type ProjectClass = { class: string; match: string[]; policy: string }
type PathClass = { class: string; prefix: string; policy: string }

export type EnvironmentPolicy = {
  version: 1
  about: string
  gcp_projects: { classes: ProjectClass[]; unclassified: string }
  local_paths: { classes: PathClass[]; other: string }
  services: { service: string; policy: string }[]
  reviewer_rules: string[]
  findings: Record<string, string>
}

const defaultFile = new URL("./environment-policy.json", import.meta.url)
let cached: { key: string; policy: EnvironmentPolicy | undefined } | undefined

// Re-read when the file changes, so editing policy needs no server restart.
// Any read or validation failure yields undefined: callers fail closed.
export function loadEnvironmentPolicy(file: URL | string = defaultFile): EnvironmentPolicy | undefined {
  try {
    const info = statSync(file)
    const key = `${String(file)}:${info.mtimeMs}:${info.size}`
    if (cached?.key === key) return cached.policy
    const policy = validate(JSON.parse(readFileSync(file, "utf8")))
    cached = { key, policy }
    return policy
  } catch {
    return undefined
  }
}

function validate(value: unknown): EnvironmentPolicy | undefined {
  const text = (item: unknown) => typeof item === "string" && item.trim().length > 0 && item.length <= 2_000
  if (!isRecord(value) || value.version !== 1 || !text(value.about)) return undefined
  const gcp = value.gcp_projects
  const local = value.local_paths
  if (!isRecord(gcp) || !Array.isArray(gcp.classes) || !text(gcp.unclassified)) return undefined
  if (!isRecord(local) || !Array.isArray(local.classes) || !text(local.other)) return undefined
  if (
    !gcp.classes.every(
      (item) =>
        isRecord(item) &&
        text(item.class) &&
        text(item.policy) &&
        Array.isArray(item.match) &&
        item.match.length > 0 &&
        item.match.every((pattern) => typeof pattern === "string" && /^[a-z][a-z0-9-]*\*?$/.test(pattern)),
    )
  )
    return undefined
  if (
    !local.classes.every(
      (item) =>
        isRecord(item) &&
        text(item.class) &&
        text(item.policy) &&
        typeof item.prefix === "string" &&
        path.isAbsolute(item.prefix) &&
        path.normalize(item.prefix) === item.prefix &&
        !item.prefix.endsWith("/"),
    )
  )
    return undefined
  if (!Array.isArray(value.services) || !value.services.every((item) => isRecord(item) && text(item.service) && text(item.policy)))
    return undefined
  if (!Array.isArray(value.reviewer_rules) || !value.reviewer_rules.every(text)) return undefined
  const findings = value.findings ?? {}
  if (!isRecord(findings) || !Object.values(findings).every(text)) return undefined
  return { ...(value as unknown as EnvironmentPolicy), findings: findings as Record<string, string> }
}

export function classifyProject(policy: EnvironmentPolicy, project: string) {
  return (
    policy.gcp_projects.classes.find((item) =>
      item.match.some((pattern) => (pattern.endsWith("*") ? project.startsWith(pattern.slice(0, -1)) : project === pattern)),
    )?.class ?? "unclassified"
  )
}

// Lexical classification of an absolute, normalized path. Callers that rely
// on the class for a write must resolve symlinks first.
export function classifyPath(policy: EnvironmentPolicy, file: string) {
  if (!path.isAbsolute(file)) return "unknown"
  const normalized = path.normalize(file)
  return (
    policy.local_paths.classes.find((item) => normalized === item.prefix || normalized.startsWith(item.prefix + path.sep))
      ?.class ?? "other"
  )
}

// What reviewers receive: the whole standing policy, plus guidance only for
// the findings present in this request.
export function reviewerPolicy(policy: EnvironmentPolicy, findings: string[] = []) {
  const guidance = Object.fromEntries(
    [...new Set(findings)].flatMap((key) => (policy.findings[key] ? [[key, policy.findings[key]]] : [])),
  )
  return {
    about: policy.about,
    gcp_projects: policy.gcp_projects,
    local_paths: policy.local_paths,
    services: policy.services,
    reviewer_rules: policy.reviewer_rules,
    ...(Object.keys(guidance).length ? { finding_guidance: guidance } : {}),
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value)
}
