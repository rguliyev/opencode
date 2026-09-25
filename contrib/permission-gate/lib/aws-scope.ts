// AWS account/profile scope policy, mirroring lib/gcp-scope.ts.
// Lives OUTSIDE plugins/ because opencode's plugin loader calls every export
// of a plugin module as a plugin factory.
import { readFileSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"

type Grant = { account: string; until: string; reason?: string; session?: string }
type Policy = { version: 1; allowed_accounts: string[]; allowed_profiles: string[] }

const policyPath = join(homedir(), ".config", "opencode", "aws-scope.json")
const accountID = /^[0-9]{12}$/

// Absent policy => no allowlist enforcement (credential-switch checks still apply),
// so adding AWS later is opt-in rather than a surprise wall of prompts.
export function loadAwsPolicy(sessions?: string[]): Policy | undefined {
  let raw: string
  try {
    raw = readFileSync(policyPath, "utf8")
  } catch {
    return undefined
  }
  const value = JSON.parse(raw) as Partial<Policy>
  if (value.version !== 1) throw new Error(`Unsupported AWS scope policy version in ${policyPath}`)
  const now = Date.now()
  const grants = Array.isArray((value as { grants?: Grant[] }).grants) ? (value as { grants?: Grant[] }).grants! : []
  const granted = grants
    .filter((g) => g && typeof g.account === "string" && typeof g.until === "string")
    .filter((g) => !g.session || (sessions?.includes(g.session) ?? false))
    .filter((g) => {
      const until = Date.parse(g.until)
      if (Number.isNaN(until)) throw new Error(`Invalid grant expiry "${g.until}" in ${policyPath}`)
      return until > now
    })
    .map((g) => g.account)
  const accounts = [...new Set([...(value.allowed_accounts ?? []), ...granted])]
  if (accounts.some((account) => !accountID.test(account))) throw new Error(`Invalid AWS account id in ${policyPath}`)
  return { version: 1, allowed_accounts: accounts, allowed_profiles: [...new Set(value.allowed_profiles ?? [])] }
}

function captures(command: string, expression: RegExp) {
  const values: string[] = []
  for (const match of command.matchAll(expression)) {
    const value = match.slice(1).find(Boolean)
    if (value) values.push(value)
  }
  return values
}

function explicitAccounts(command: string) {
  return new Set([
    ...captures(command, /arn:aws[a-z-]*:[^:\s]*:[^:\s]*:([0-9]{12}):/g),
    ...captures(command, /--account-ids?(?:=|\s+)(?:"|')?([0-9]{12})/g),
    ...captures(command, /(?:AWS_ACCOUNT_ID|TF_VAR_aws_account_id)\s*=\s*(?:"|')?([0-9]{12})/g),
  ])
}

function explicitProfiles(command: string) {
  return new Set([
    ...captures(command, /--profile(?:=|\s+)(?:"([^"]+)"|'([^']+)'|([A-Za-z0-9._-]+))/g),
    ...captures(command, /AWS_PROFILE\s*=\s*(?:"([^"]+)"|'([^']+)'|([A-Za-z0-9._-]+))/g),
  ])
}

// Identity or credential switching is scope escalation regardless of allowlist.
export function attemptsAwsIdentitySwitch(command: string) {
  return (
    /\baws\b[^\n;|&]*\bsts\s+(?:assume-role|assume-role-with-web-identity|assume-role-with-saml|get-session-token|get-federation-token)\b/i.test(command) ||
    /\baws\b[^\n;|&]*\bconfigure\s+(?:set|import|sso)\b/i.test(command) ||
    /\baws\b[^\n;|&]*\bsso\s+(?:login|logout)\b/i.test(command) ||
    /\b(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|AWS_ROLE_ARN|AWS_WEB_IDENTITY_TOKEN_FILE)\s*=/.test(command) ||
    /(?:--profile|AWS_PROFILE)(?:=|\s+)(?:"|')?(?:\$|`)/.test(command)
  )
}

export function awsScopeReviewMessage(command: string, sessions?: string[]) {
  if (!/\baws\b|arn:aws|AWS_/.test(command)) return undefined
  if (attemptsAwsIdentitySwitch(command)) return "AWS identity or credential selection requires human review"
  const policy = loadAwsPolicy(sessions)
  if (!policy) return undefined
  const deniedAccounts = [...explicitAccounts(command)].filter((a) => !policy.allowed_accounts.includes(a))
  if (deniedAccounts.length > 0) {
    return `AWS account${deniedAccounts.length === 1 ? "" : "s"} ${deniedAccounts.join(", ")} require human review`
  }
  if (policy.allowed_profiles.length > 0) {
    const deniedProfiles = [...explicitProfiles(command)].filter((p) => !policy.allowed_profiles.includes(p))
    if (deniedProfiles.length > 0) {
      return `AWS profile${deniedProfiles.length === 1 ? "" : "s"} ${deniedProfiles.join(", ")} require human review`
    }
  }
  return undefined
}
