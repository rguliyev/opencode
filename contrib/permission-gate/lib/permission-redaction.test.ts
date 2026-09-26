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
