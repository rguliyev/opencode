import { readFileSync } from "node:fs"
import path from "node:path"
import { expect, test } from "bun:test"
import { sanitizeReviewText, sanitizeReviewValue } from "./permission-redaction"

test("redacts credential values but keeps command action and target", () => {
  const token = "sk-" + "A".repeat(40)
  const command = `curl -X POST -H 'Authorization: Bearer ${token}' https://api.example.test/deploy`
  const safe = sanitizeReviewText(command)
  expect(safe.complete).toBe(true)
  expect(safe.value).toContain("curl -X POST")
  expect(safe.value).toContain("https://api.example.test/deploy")
  expect(safe.value).toContain("[REDACTED:CREDENTIAL]")
  expect(safe.value).not.toContain(token)
})

test("redacts provider tokens, URL credentials, query values, and private keys", () => {
  const github = "ghp_" + "B".repeat(36)
  const oauth = "ya29." + "C".repeat(32)
  const key = "-----BEGIN PRIVATE KEY-----\n" + "D".repeat(48) + "\n-----END PRIVATE KEY-----"
  const input = `git clone https://alice:password123@github.com/org/repo; echo ${github}; curl 'https://example.test/?access_token=${oauth}'; echo '${key}'`
  const safe = sanitizeReviewText(input)
  expect(safe.complete).toBe(true)
  expect(safe.value).not.toContain("password123")
  expect(safe.value).not.toContain(github)
  expect(safe.value).not.toContain(oauth)
  expect(safe.value).not.toContain(key)
  expect(safe.value).toContain("github.com/org/repo")
  expect(safe.value).toContain("[REDACTED:PRIVATE_KEY]")
})

test("recursively sanitizes script and context without changing shell references", () => {
  const password = "correct-horse-battery-staple"
  const raw = {
    command: "env API_KEY=${API_KEY} bash deploy.sh",
    context: { purpose: `deploy with password=${password}` },
    scripts: [{ path: "deploy.sh", content: `PASSWORD='${password}'\necho "$API_KEY"` }],
  }
  const safe = sanitizeReviewValue(raw)
  expect(safe.complete).toBe(true)
  expect(safe.value.command).toBe(raw.command)
  expect(safe.value.context.purpose).toContain("[REDACTED:CREDENTIAL]")
  expect(safe.value.scripts[0].content).toContain('echo "$API_KEY"')
  expect(JSON.stringify(safe.value)).not.toContain(password)
})

test("redacts short passwords and command-line user credentials", () => {
  const safe = sanitizeReviewText("curl -u alice:xy --password=ab https://example.test/?token=z")
  expect(safe.value).toContain("alice:[REDACTED:PASSWORD]")
  expect(safe.value).toContain("--password=[REDACTED:CREDENTIAL]")
  expect(safe.value).toContain("?token=[REDACTED:CREDENTIAL]")
  expect(safe.value).not.toContain("alice:xy")
})

test("redacts entire quoted values, including spaces and shell separators", () => {
  const secret = "correct horse; battery staple"
  const safe = sanitizeReviewText(`PASSWORD="${secret}" curl --password='${secret}'`)
  expect(safe.value).not.toContain(secret)
  expect(safe.value).not.toContain("battery staple")
  expect(safe.value).toContain('PASSWORD="[REDACTED:CREDENTIAL]"')
  expect(safe.value).toContain("--password='[REDACTED:CREDENTIAL]'")
})

test("redacts full quoted CLI passwords", () => {
  const safe = sanitizeReviewText("curl -u 'alice:two words' https://example.test; docker login -p 'three words'")
  expect(safe.value).not.toContain("two words")
  expect(safe.value).not.toContain("three words")
  expect(safe.value).toContain("alice:[REDACTED:PASSWORD]")
})

test("redacts full unquoted YAML secret scalars", () => {
  const safe = sanitizeReviewText("password: correct horse battery staple\nmode: production")
  expect(safe.value).toContain("password: [REDACTED:CREDENTIAL]")
  expect(safe.value).not.toContain("horse battery")
  expect(safe.value).toContain("mode: production")
})

test("does not mistake type declarations or counters for literal credentials", () => {
  const source = "type Config = { password: string; token_count: number }; API_KEY=${API_KEY}"
  const safe = sanitizeReviewText(source)
  expect(safe.value).toBe(source)
  expect(safe.kinds).toEqual([])
})

test("strips invisible control characters from review copies", () => {
  const safe = sanitizeReviewText("git st\u200Batus")
  expect(safe.value).toBe("git status")
  expect(safe.kinds).toContain("INVISIBLE_CONTROL")
})

test("redaction stays fast on long unbroken runs", () => {
  // Unbounded identifier quantifiers once took ~5 s on 23 KB of letters,
  // blocking every permission review behind a long human message.
  for (const text of ["a".repeat(50_000), "token_" + "b".repeat(50_000) + "=value", "x:".repeat(25_000)]) {
    const started = performance.now()
    sanitizeReviewText(text)
    expect(performance.now() - started).toBeLessThan(500)
  }
})

test("IAM member strings are not URL passwords", () => {
  const member = 'members = ["serviceAccount:logs-writer@example.invalid", "user:alice@example.invalid"]'
  expect(sanitizeReviewText(member).value).toBe(member)
  expect(sanitizeReviewText("https://admin:hunter2secret@db.example.invalid/x").value).toContain("[REDACTED:PASSWORD]")
  expect(sanitizeReviewText("postgres://app:" + "s3cretvalue@db.internal/app").value).toContain("[REDACTED:PASSWORD]")
})

test("container image digests are not URL passwords", () => {
  const image = "image: python:3.13-slim@sha256:79e7a9b9ff1cbceff819f856fb374477792a5967759d94df266de7b7b4120e6f"
  expect(sanitizeReviewText(image).value).toBe(image)
  expect(sanitizeReviewText("https://deploy:" + "hunter2value@registry.example.invalid/v2").value).toContain(
    "[REDACTED:PASSWORD]",
  )
})

test("mapping literals with service accounts are not URL passwords", () => {
  const mapping =
    '"https://stg.grafana.example":("grp-logs-stg","grafana-logs-r@stg-project.iam.gserviceaccount.com"),'
  expect(sanitizeReviewText(mapping).value).toBe(mapping)
  expect(sanitizeReviewText("https://admin:" + "S3cretValue9@db.example.invalid").value).toContain("[REDACTED:PASSWORD]")
})

test("punctuation after a secret-like key is not a credential", () => {
  const label = 'echo "=== shared cluster ESO / ClusterSecretStore ==="'
  expect(sanitizeReviewText(label).value).toBe(label)
  expect(sanitizeReviewText("API_KEY=" + "abc123def456").value).toContain("[REDACTED:CREDENTIAL]")
})

test("shell default-value expansions in sed templates are not URL passwords", () => {
  const line = 'sed -i -e "s@{{ cpurequest }}@${KUBE_PROXY_CPU_REQUEST:-100m}@g" "${src_file}"'
  expect(sanitizeReviewText(line).value).toBe(line)
})

test("date -u format strings are not curl -u credentials", () => {
  for (const command of ["date -u '+now_utc=%Y-%m-%dT%H:%M:%SZ'", 'date -u "+%H:%M"', "date -u +%H:%M:%S"])
    expect(sanitizeReviewText(command).value).toBe(command)
  expect(sanitizeReviewText("curl -u admin:" + "S3cretValue9 https://api.example.invalid").value).toContain("[REDACTED:PASSWORD]")
})

test("documentation placeholders are not credentials", () => {
  for (const line of ["NOMAD_TOKEN=<token> nomad status", "token: <your-token>", 'api_key="<api-key>"'])
    expect(sanitizeReviewText(line).value).toBe(line)
  expect(sanitizeReviewText("NOMAD_TOKEN=<tok>" + "en123 nomad status").value).toContain("[REDACTED:CREDENTIAL]")
})

test("credential file paths and closing quotes are not credentials", () => {
  for (const line of [
    "grep -F -c 'tokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token'",
    "password_file = ~/.config/app/pass",
    `test "$(printf '%s\\n' "\${CFG}" | grep -E -c '^[[:space:]]*token:')" -eq 0\necho 'done'`,
  ])
    expect(sanitizeReviewText(line).value).toBe(line)
  expect(sanitizeReviewText("tokenFile: " + "abcDEF123456").value).toContain("[REDACTED:CREDENTIAL]")
  expect(sanitizeReviewText("token: '" + "abc def ghi" + "'").value).toContain("[REDACTED:CREDENTIAL]")
  expect(sanitizeReviewText("token: '" + "abcDEF123456").value).toContain("[REDACTED:CREDENTIAL]")
})

test("printf format verbs are not URL passwords", () => {
  const line = '{{- $ref = printf "%s:%s@%s" $repo $tag $digest -}}'
  expect(sanitizeReviewText(line).value).toBe(line)
  expect(sanitizeReviewText("https://admin:" + "S3cretValue9@db.example.invalid").value).toContain("[REDACTED:PASSWORD]")
})

test("prose after a secret-like key and backticked IAM members are not credentials", () => {
  for (const line of [
    "e2b-test.dev needs the dev-scoped token: the adapter reads its zone-owning secret",
    "grant `group:data-readers@e2b.dev` to `roles/bigquery.dataViewer`",
    "87. **`user:someone@e2b.dev` gets the role pair",
  ])
    expect(sanitizeReviewText(line).value).toBe(line)
  expect(sanitizeReviewText("token: " + "abcDEF123456").value).toContain("[REDACTED:CREDENTIAL]")
})

test("function calls and template placeholders are not credential values", () => {
  for (const line of ["    token = subprocess.run(", 'f"--secret={SECRETS[host]}"', "password = getpass.getpass()"])
    expect(sanitizeReviewText(line).value).toBe(line)
  // The shipped Grafana helper handles its token only in code.
  const helper = readFileSync(path.join(import.meta.dir, "../bin/grafana-query"), "utf8")
  expect(sanitizeReviewText(helper).kinds).toEqual([])
  expect(sanitizeReviewText("token = " + "abcDEF123456").value).toContain("[REDACTED:CREDENTIAL]")
})

test("jq field paths after a token-like key are not credentials", () => {
  const line = "jq '{sa:.spec.template.spec.serviceAccountName,automountServiceAccountToken:.spec.template.spec.automountServiceAccountToken}'"
  expect(sanitizeReviewText(line).value).toBe(line)
  expect(sanitizeReviewText("token: " + ".abcDEF123456").value).toContain("[REDACTED:CREDENTIAL]")
})
