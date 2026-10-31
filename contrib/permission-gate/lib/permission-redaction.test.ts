import { readFileSync } from "node:fs"
import path from "node:path"
import { expect, test } from "bun:test"
import { containsCredentialMaterial, sanitizeReviewText, sanitizeReviewValue } from "./permission-redaction"

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
  const bracketed = "jq '{tokenVolume:[.spec.template.spec.volumes[]|select(.projected.sources)]}'"
  expect(sanitizeReviewText(bracketed).value).toBe(bracketed)
  expect(sanitizeReviewText("token: " + ".abcDEF123456").value).toContain("[REDACTED:CREDENTIAL]")
})

test("an expression after a token-named key is not a credential", () => {
  const jq = `jq -c '{types:[.metricDescriptors[]?.type],nextPageToken:(.nextPageToken//null)}'`
  expect(sanitizeReviewText(jq)).toMatchObject({ value: jq, kinds: [] })
  expect(sanitizeReviewText("token: $API_TOKEN").value).toBe("token: $API_TOKEN")
  // A literal value after the same key is still masked.
  expect(sanitizeReviewText("nextPageToken: Zx9fA7c2Lm4Qw8Rt").value).toBe("nextPageToken: [REDACTED:CREDENTIAL]")
  expect(sanitizeReviewText("password=hunter2-real").value).toBe("password=[REDACTED:CREDENTIAL]")
})

test("a go-getter module source is not a user:password URL", () => {
  const source = `source = "git::git@github.com:e2b-dev/terraform-modules.git//gcp/x?ref=gcp-x-v1.0.0"`
  expect(sanitizeReviewText(source)).toMatchObject({ value: source, kinds: [] })
  // Real URL credentials are still masked, with or without a getter prefix.
  expect(sanitizeReviewText("git::https://deploy:Sup3rS3cret@github.com/org/repo.git").kinds).toContain("PASSWORD")
  expect(sanitizeReviewText("https://user:hunter2pass@example.com/x").kinds).toContain("PASSWORD")
})

test("a credential-named setting holding a file path is not masked; a slash-led secret still is", () => {
  const path = "GOOGLE_APPLICATION_CREDENTIALS=/home/u/.config/gcloud/application_default_credentials.json gcloud info"
  expect(sanitizeReviewText(path).value).toBe(path)
  expect(sanitizeReviewText("API_TOKEN=/Xq9aB3kLmN0pQ7rS2tUv").value).toContain("[REDACTED:CREDENTIAL]")
})

test("a token-shaped literal that declares itself fake is test data, not credential material", () => {
  const real = "xoxb-" + "1234567890-0987654321-AbCdEfGhIjKlMnOpQrStUv"
  expect(containsCredentialMaterial(`const token = "${real}"`)).toBe(true)
  expect(containsCredentialMaterial('const token = "xoxb-fixture-bot-token-for-incident-eval"')).toBe(false)
  expect(containsCredentialMaterial("url = 'https://hooks.slack.com/services/T000/B000/fakefakefakefake'")).toBe(false)
  // A fake literal next to a real one still counts.
  expect(containsCredentialMaterial(`"xoxb-fixture-bot-token-for-incident-eval" "${real}"`)).toBe(true)
  // Provider test-mode keys are real keys.
  expect(containsCredentialMaterial('stripe = "sk_test_' + "4eC39HqLyjWDarjtT1zdp7dc" + '"')).toBe(true)
  // Redaction still masks the fake value in what the reviewers see.
  expect(sanitizeReviewText('const token = "xoxb-fixture-bot-token-for-incident-eval"').value).not.toContain("xoxb-fixture")
})

test("an unquoted property path after a credential-named key is a reference, not a value", () => {
  const code = "\t\t\tapiKey: config.e2b.apiKey,\n\t\t\ttoken = opts?.auth.token;\n\t\t\tpassword: user.password }"
  const safe = sanitizeReviewText(code)
  expect(safe.value).toBe(code)
  expect(safe.kinds).toEqual([])
  // A negated reference is still a reference.
  expect(sanitizeReviewText("  hasGithubToken: !!cfg.githubToken,\n  noToken: !opts.token;").value).toBe(
    "  hasGithubToken: !!cfg.githubToken,\n  noToken: !opts.token;",
  )
  // Quoted, it is a literal string that happens to contain dots.
  expect(sanitizeReviewText('password: "hunter.two"').value).toContain("[REDACTED:CREDENTIAL]")
  expect(sanitizeReviewText("token = ya29." + "a".repeat(30)).value).toContain("[REDACTED:")
})

test("an unquoted index or call after a credential-named key is code reading the value, not a value", () => {
  const code = '    token = match[1].trim().replace(/^["\'](.*)["\']$/, "$1");\n  password: getSecret(name),\n  apiKey = env?.["API_KEY"]'
  const safe = sanitizeReviewText(code)
  expect(safe.value).toBe(code)
  expect(safe.kinds).toEqual([])
  // A plain unquoted value is still a value.
  expect(sanitizeReviewText("password = hunter2rocks").value).toContain("[REDACTED:CREDENTIAL]")
})

test("an unquoted name declared earlier in the same text is a variable, not a value", () => {
  const code = "let apiKey = '';\napiKey = line.slice(12).trim();\nprocess.env.E2B_API_KEY = apiKey;\n"
  const safe = sanitizeReviewText(code)
  expect(safe.value).toBe(code)
  expect(safe.kinds).toEqual([])
  // A Python assignment earlier in the text declares the name too.
  const py = "sec = P['stagingClientSecret']\ncfg = {\n    'clientSecret': sec_value\n}\nsec_value = sec\nnew = {'clientSecret': sec}\n"
  expect(sanitizeReviewText(py).value).toContain("'clientSecret': sec}")
  const pyBlock = "staging_client_sec = P['stagingClientSecret']\nnew_cfg['stagingOauth'] = {\n    'clientSecret': staging_client_sec\n}\n"
  expect(sanitizeReviewText(pyBlock).value).toBe(pyBlock)
  // Without a declaration the same word is still treated as a value.
  expect(sanitizeReviewText("process.env.E2B_API_KEY = apiKeyValue1;").value).toContain("[REDACTED:CREDENTIAL]")
})

test("an unquoted UPPER_SNAKE constant after a credential-named key is a reference, not a value", () => {
  const code = "\t\t\tclientSecret: STAGING_CLIENT_SECRET,\n\tconst token = SLACK_BOT_TOKEN;\n"
  const safe = sanitizeReviewText(code)
  expect(safe.value).toBe(code)
  expect(safe.kinds).toEqual([])
  // Mixed or lower case is still a value.
  expect(sanitizeReviewText("clientSecret: Zx91kLmQ02pRtY_ab,").value).toContain("[REDACTED:CREDENTIAL]")
})

test("an operator opening an expression after a credential-named key is code, not a value", () => {
  const code = "let token = await fetchToken();\n  async onUnauthorized() { token = await fetchToken(); }\nconst source = new TokenSource(cfg)\n"
  const safe = sanitizeReviewText(code)
  expect(safe.value).toBe(code)
  expect(safe.kinds).toEqual([])
  // A word before a bare value, not a call or property, is still masked.
  expect(sanitizeReviewText("let token = await hunter2rocks9").value).toContain("[REDACTED:CREDENTIAL]")
  expect(sanitizeReviewText("password = hunter2 rocks9").value).toContain("[REDACTED:CREDENTIAL]")
})

test("a header name in its own quoted string, with the value read from a file, is not a credential", () => {
  const command = `{ printf 'X-API-Key: '; cat ../run/dev-api-key; echo; } | curl -sS -H @- http://127.0.0.1:15001/sandboxes | python3 -c "print('live')"`
  const safe = sanitizeReviewText(command)
  expect(safe.value).toBe(command)
  expect(safe.kinds).toEqual([])
  // The value inside the quotes is still masked.
  expect(sanitizeReviewText("printf 'X-API-Key: hunter2value'").value).toContain("[REDACTED:CREDENTIAL]")
  expect(sanitizeReviewText(`bash -c 'export PASSWORD="hunter2value"'`).value).toContain("[REDACTED:CREDENTIAL]")
})

test("a printf format verb after a credential-named key is a template, not a value", () => {
  const command = `KEY=$(cat ./dev-api-key); printf 'X-API-Key: %s\\n' "$KEY" | curl -sS -H @- http://127.0.0.1:15001/templates`
  const safe = sanitizeReviewText(command)
  expect(safe.value).toBe(command)
  expect(safe.kinds).toEqual([])
  expect(sanitizeReviewText(`printf "token=%-10s\\t" "$T"`).kinds).toEqual([])
  expect(sanitizeReviewText("printf 'X-API-Key: %shunter2'").value).toContain("[REDACTED:CREDENTIAL]")
})

test("an assigned value that declares itself fake is a fixture, not a credential", () => {
  const line = "export TESTS_E2B_API_KEY=fake-unused-api-key-fixture TESTS_SANDBOX_TEMPLATE_ID=fake-template-fixture"
  expect(sanitizeReviewText(line).value).toBe(line)
  expect(sanitizeReviewText('password: "dummy-value"').kinds).toEqual([])
  // A real-looking value stays masked; "example" alone is not a declaration.
  expect(sanitizeReviewText("TESTS_E2B_API_KEY=k8Zq2Lx9PwV4mT7c").value).toContain("[REDACTED:CREDENTIAL]")
})

test("a boolean or type after a credential-named key keeps its meaning before closing punctuation", () => {
  const prose = "seccompProfile: {type: RuntimeDefault}, automountServiceAccountToken: false). Then token: none."
  expect(sanitizeReviewText(prose).value).toBe(prose)
  expect(sanitizeReviewText("(apiToken: string),").kinds).toEqual([])
  expect(sanitizeReviewText("token: k8Zq2Lx9PwV4mT7c).").value).toContain("[REDACTED:CREDENTIAL]")
})

test("a credential-named key with its value on the next line is a YAML mapping, not a value", () => {
  const manifest = "  volumes:\n    - name: node-readiness-api-token\n      projected:\n        sources:\n          - serviceAccountToken:\n              path: token\n              expirationSeconds: 3600\n"
  expect(sanitizeReviewText(manifest).value).toBe(manifest)
  expect(sanitizeReviewText("token: k8Zq2Lx9PwV4mT7c\n").value).toContain("[REDACTED:CREDENTIAL]")
})

test("a private-key header in code is not a key; a header followed by key material is", () => {
  const code = "if (pem.startsWith('-----BEGIN RSA PRIVATE KEY-----')) {\n  // convert PKCS#1 to PKCS#8\n}\nif (!pem.startsWith('-----BEGIN PRIVATE KEY-----')) throw new Error('bad key')"
  expect(containsCredentialMaterial(code)).toBe(false)
  expect(sanitizeReviewText(code).complete).toBe(true)
  const body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7" + "Q".repeat(40)
  expect(containsCredentialMaterial(`-----BEGIN PRIVATE KEY-----\n${body}\n`)).toBe(true)
  expect(containsCredentialMaterial(`"-----BEGIN PRIVATE KEY-----\\n${body}\\n"`)).toBe(true)
})

test("a private-key block whose body says it is fake is a fixture", () => {
  expect(containsCredentialMaterial("'docs/leak.md': '-----BEGIN PRIVATE KEY-----\\nfake-private-key\\n-----END PRIVATE KEY-----\\n'")).toBe(false)
  const body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7" + "Q".repeat(40)
  expect(containsCredentialMaterial(`-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----`)).toBe(true)
})
