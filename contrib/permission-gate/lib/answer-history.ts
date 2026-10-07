// How the human answered recent gate prompts, per finding, read from the
// gate's outcome logs (outcomes/YYYY-MM-DD.jsonl, one record per asked call
// with its reasons and the human's answer). Only counts are produced; no
// command, path, or reason text leaves this module. Lives OUTSIDE plugins/
// because opencode's plugin loader calls every export of a plugin module as
// a plugin factory.
import { readFileSync, readdirSync, statSync } from "node:fs"
import path from "node:path"

export type AnswerCounts = { asked: number; approved: number; denied: number; days: number }

// Reason strings, current and from earlier gate versions, mapped to finding
// keys. Older reasons that mixed hard and soft cases (for example "human-only
// operation" or "credential or secret access") are deliberately unmapped.
const keys: [RegExp, string][] = [
  [/^(?:credential-like literal|sensitive literal in action|skill contains credential literal)/, "credential_pattern"],
  [/^(?:GCP project chosen dynamically|GCP project or credential selection requires human review)/, "gcp_dynamic_project"],
  [/^(?:inspected script )?uses ambient credentials/, "ambient_credentials"],
  [/^recursive delete inside writable local paths/, "local_delete"],
  [/^(?:human-only policy or data change may apply|edits an auth, permission)/, "policy_file_edit"],
  [
    /^(?:sensitive file or search target|sensitive matched path|file or search target name suggests|glob pattern or path names|\d+ matched file name)/,
    "sensitive_name",
  ],
  [/^custom tool \S+ has no attested effect/, "unattested_tool"],
  [/^(?:\S+ requests .* outside the workdir|glob reaches outside)/, "external_path"],
  [/^no script evidence/, "missing_script_evidence"],
  [/^publish:/, "publish"],
  [/^token-read:/, "token_read"],
]

export function findingKey(reason: string) {
  return keys.find(([pattern]) => pattern.test(reason))?.[1]
}

const maxFileBytes = 4 * 1024 * 1024

export function answerHistory(dir: string, now = Date.now(), days = 7) {
  const counts = new Map<string, AnswerCounts>()
  const since = new Date(now - days * 86_400_000).toISOString().slice(0, 10)
  let files: string[]
  try {
    files = readdirSync(dir)
      .filter((name) => /^\d{4}-\d{2}-\d{2}\.jsonl$/.test(name) && name.slice(0, 10) >= since)
      .sort()
      .slice(-days - 1)
  } catch {
    return counts
  }
  for (const name of files) {
    const file = path.join(dir, name)
    let text: string
    try {
      if (statSync(file).size > maxFileBytes) continue
      text = readFileSync(file, "utf8")
    } catch {
      continue
    }
    for (const line of text.split("\n")) {
      let record: unknown
      try {
        record = line ? JSON.parse(line) : undefined
      } catch {
        continue
      }
      if (!record || typeof record !== "object" || Array.isArray(record)) continue
      const { outcome, reasons } = record as { outcome?: unknown; reasons?: unknown }
      if (typeof outcome !== "string" || !Array.isArray(reasons)) continue
      const found = new Set(reasons.flatMap((reason) => (typeof reason === "string" ? (findingKey(reason) ?? []) : [])))
      for (const key of found) {
        const entry = counts.get(key) ?? { asked: 0, approved: 0, denied: 0, days }
        entry.asked += 1
        if (outcome === "approved") entry.approved += 1
        if (outcome === "denied") entry.denied += 1
        counts.set(key, entry)
      }
    }
  }
  return counts
}
