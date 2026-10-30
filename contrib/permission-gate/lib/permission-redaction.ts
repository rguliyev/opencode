// Redact review copies only. Never apply this to the arguments OpenCode executes.
export type RedactionResult<T> = {
  value: T
  kinds: string[]
  complete: boolean
}

const marker = (kind: string) => `[REDACTED:${kind}]`
const markerPattern = /\[REDACTED:[A-Z_]+\]/g
// Values that name where a secret comes from rather than containing it,
// including Terraform references such as data.google_secret_manager_*.
// A function call (`token = subprocess.run(`), a template placeholder
// (`f"--secret={SECRETS[host]}"`, `{token}`), or a jq/JSON path
// (`automountServiceAccountToken:.spec.template...`) is code, not a value.
const reference =
  /^(?:\$|process\.env\b|os\.environ\b|os\.getenv\b|getenv\(|env\(|\[REDACTED:|(?:data|var|local|module|dependency|include|each|self)\.[A-Za-z_]|[A-Za-z_][A-Za-z0-9_.]*\(|\{[A-Za-z_]|[[(]*\.[A-Za-z_][A-Za-z0-9_]*(?:\.|\[))/i

// tokenFile: /var/run/secrets/.../token names where a credential is read
// from; the path is not the credential.
const pathSetting = /(?:file|path|dir)["']?\s*(?:=|:)\s*["']?$/i
const pathValue = /^(?:\/|~\/|\.\.?\/)[A-Za-z0-9._/-]*$/
// A credential-named setting whose value is a file path
// (GOOGLE_APPLICATION_CREDENTIALS=/x/adc.json) names where a credential is,
// not the credential. The directory and file-extension shape keeps a base64
// value that happens to start with "/" from passing.
const credentialFilePath = /^(?:\/|~\/|\.\.?\/)(?:[A-Za-z0-9._-]+\/)+[A-Za-z0-9_-][A-Za-z0-9._-]*\.(?:json|pem|key|p12|crt|yaml|yml|toml|ini|cfg|conf|txt)$/
// A documentation placeholder such as NOMAD_TOKEN=<token> holds no value.
const placeholder = /^<[A-Za-z][A-Za-z0-9_.-]{0,62}>$/
// printf 'X-API-Key: %s\n' "$KEY" fills the value in at run time; the format
// verbs (and escapes) are the template, not the credential.
const formatVerbs = /^(?:%[-+ #0-9.]*[a-zA-Z]|\\[nrt])+$/
// Unquoted, `apiKey: config.e2b.apiKey,` reads a property; the value lives
// elsewhere. Quoted, the same text is a literal. Provider tokens with dots
// (ya29.…) are still masked by their own pattern.
const propertyPath = /^[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*)+\s*[;,})]?$/
// Code that reads the value elsewhere: `token = match[1].trim()` or
// `password = getSecret(name)` indexes or calls something; it is not a value.
const codeExpression = /^[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*)*\??\.?[[(]/
// `clientSecret: STAGING_CLIENT_SECRET` names a constant defined elsewhere; an
// UPPER_SNAKE name with no lowercase is a reference, not the value.
const constantName = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+[,;)}]?$/

// Provider-issued token formats and signed JWTs: values with these shapes are
// real credentials far more often than not, unlike the generic patterns below.
// `process.env.API_KEY = apiKey;` after `let apiKey = ...`, or Python's
// `'clientSecret': sec` after `sec = P['x']`, uses a variable assigned earlier in
// the same text; the name is a reference, not a value.
function assignedEarlier(name: string, before: string) {
  if (!/^[A-Za-z_$][\w$]*$/.test(name)) return false
  const escaped = name.replace(/\$/g, "\\$")
  return new RegExp(`\\b(?:let|const|var)\\s+${escaped}\\b|^[ \\t]*${escaped}[ \\t]*=(?!=)`, "m").test(before)
}

const providerToken =
  /\b(?:sk-(?:proj|ant|live|test)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{25,}|(?:AKIA|ASIA)[A-Z0-9]{16}|ya29\.[A-Za-z0-9_-]{20,}|4\/0A[A-Za-z0-9_-]{20,}|1\/\/[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|pypi-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9_-]{20,}|sk_(?:live|test)_[A-Za-z0-9]{16,})\b/
const jwt = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/
const webhook = /https:\/\/(?:hooks\.slack\.com\/services|discord(?:app)?\.com\/api\/webhooks)\/[^\s'";|]{12,}/i

// High-precision credential material: a provider-format token, signed JWT,
// private key, or chat webhook URL. The permission gate treats these as a hard
// human gate; the generic assignment/header/URL-password patterns are only
// evidence for its reviewers, because they are usually names or references.
// A token-shaped literal whose own text says it is not real
// (xoxb-fixture-..., a webhook URL ending in /fake...) is test data, not a
// credential. Provider prefixes such as sk_test_ are real keys, so "test"
// alone does not count.
const declaredFake = /fixture|fake|dummy|example|placeholder|mock|sample|redacted|notreal|changeme/i

function realMatch(pattern: RegExp, text: string) {
  const global = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g")
  return [...text.matchAll(global)].some((match) => !declaredFake.test(match[0]))
}

// A key is the header followed by its base64 body (raw or JSON-escaped
// newlines), or a complete BEGIN...END block; code that only compares or
// mentions the header holds no key.
const privateKeyMaterial =
  /-----BEGIN [A-Z ]*PRIVATE KEY-----(?:(?:\\[rn]|\s)*[A-Za-z0-9+/]{40,}|[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)/

export function containsCredentialMaterial(text: string) {
  return (
    realMatch(providerToken, text) ||
    realMatch(jwt, text) ||
    realMatch(webhook, text) ||
    realMatch(privateKeyMaterial, text)
  )
}

// This is deliberately a bounded, local detector rather than a claim that
// arbitrary passwords can be recognized. Unrecognized values remain a risk.
const residualCredential =
  /\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{25,}|(?:AKIA|ASIA)[A-Z0-9]{16}|ya29\.[A-Za-z0-9_-]{20,}|4\/0A[A-Za-z0-9_-]{20,}|1\/\/[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})\b|-----BEGIN [A-Z ]*PRIVATE KEY-----(?:\\[rn]|\s)*[A-Za-z0-9+/]{40,}/i

// In `printf 'X-API-Key: '; cat key`, the quote after the colon closes the
// string the header name sits in; it does not open a value. Counted on the
// current line, so an earlier line's unbalanced quote cannot flip it.
function opensQuote(text: string, quote: string) {
  const line = text.slice(text.lastIndexOf("\n") + 1, -1)
  return line.split(quote).length % 2 === 1
}

function sanitizeText(input: string): RedactionResult<string> {
  const kinds = new Set<string>()
  let value = input
  const replaceFull = (pattern: RegExp, kind: string) => {
    value = value.replace(pattern, (found) => {
      kinds.add(kind)
      return marker(kind)
    })
  }
  const replaceValue = (
    pattern: RegExp,
    kind: string,
    shouldRedact: (prefix: string, secret: string, before: string) => boolean = () => true,
  ) => {
    value = value.replace(pattern, (found, prefix: string, secret: string, offset: number, whole: string) => {
      if (
        !secret ||
        reference.test(secret) ||
        placeholder.test(secret.trim()) ||
        formatVerbs.test(secret.trim()) ||
        // AGENTS.md has fixtures say so in the value itself (fake-…-fixture).
        /fake|fixture|dummy|notreal/i.test(secret) ||
        (pathSetting.test(prefix) && pathValue.test(secret.trim())) ||
        credentialFilePath.test(secret.trim()) ||
        (!/["'`]\s*$/.test(prefix) &&
          // `hasToken: !!cfg.githubToken` negates a property path; the `!` does not
          // turn the reference into a value.
          (propertyPath.test(secret.trim().replace(/^!+/, "")) ||
            codeExpression.test(secret.trim().replace(/^!+/, "")) ||
            constantName.test(secret.trim()) ||
            assignedEarlier(secret.trim().replace(/[,;)}]$/, ""), whole.slice(0, offset)))) ||
        !shouldRedact(prefix, secret, whole.slice(0, offset))
      )
        return found
      kinds.add(kind)
      return prefix + marker(kind)
    })
  }

  replaceFull(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "PRIVATE_KEY")
  // Quantifiers are bounded: unbounded runs backtrack quadratically, and a
  // 23 KB run of letters took seconds, blocking every permission review.
  // IAM member strings such as "serviceAccount:name@project.iam..." have the
  // same user:secret@host shape; without a URL scheme they are not passwords.
  replaceValue(
    // Container references such as python:3.13-slim@sha256:<digest> have the
    // same name:tag@host shape; a digest after @ is not a host.
    // Quotes, parentheses, commas, and braces cannot appear unencoded in URL
    // userinfo; excluding them keeps "https://host": ("name", "sa@...") and
    // sed templates like s@x@${VAR:-100m}@g from reading as user:password@host.
    /((?:https?:\/\/)?[^\s/:@"'(),{}]{1,256}:)([^\s/@"'(),{}]{1,256})(?=@(?!sha(?:256|384|512):)[^\s/]+)/gi,
    "PASSWORD",
    // printf "%s:%s@%s" repo tag digest builds an image reference; a format
    // verb is not a password.
    (prefix, secret) =>
      !/^%[-+ #0-9.]*[a-zA-Z]$/.test(secret) &&
      // go-getter sources (git::git@github.com:org/repo.git, as used by every
      // Terraform/Terragrunt module source) force a getter with `name::`;
      // the second colon is not a user:password separator.
      !(/^(?:git|hg|s3|gcs|https?|file):$/i.test(prefix) && secret.startsWith(":")) &&
      (/^https?:\/\//i.test(prefix) ||
        !/(?:^|["'`\s=,[(])(?:serviceAccount|user|group|domain|principal|principalSet|deleted):$/i.test(prefix)),
  )
  replaceValue(
    /(https:\/\/(?:hooks\.slack\.com\/services|(?:discord(?:app)?\.com)\/api\/webhooks)\/)([^\s'";|]{12,})/gi,
    "WEBHOOK",
  )
  replaceValue(
    /((?:authorization|proxy-authorization|x-api-key|api-key|x-auth-token|cookie|set-cookie)\s*:\s*(?:(?:Bearer|Basic|Token)\s+)?["']?)([^\s'";|]+)/gi,
    "CREDENTIAL",
  )
  replaceValue(
    /([?&](?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|secret|client[_-]?secret|private[_-]?key|token)=)([^\s&#'";|]+)/gi,
    "CREDENTIAL",
  )
  // Quoted values can contain spaces, semicolons, and shell metacharacters.
  // Handle the whole quoted span before the shorter unquoted patterns below.
  replaceValue(
    /(--(?:api[-_]?key|access[-_]?token|auth[-_]?token|oauth2[-_]?bearer|password|passwd|secret|client[-_]?secret|private[-_]?key|userpwd)(?:=|\s+)")((?:\\.|[^"\\])*)/gi,
    "CREDENTIAL",
  )
  replaceValue(
    /(--(?:api[-_]?key|access[-_]?token|auth[-_]?token|oauth2[-_]?bearer|password|passwd|secret|client[-_]?secret|private[-_]?key|userpwd)(?:=|\s+)')((?:\\.|[^'\\])*)/gi,
    "CREDENTIAL",
  )
  replaceValue(
    /(--(?:api[-_]?key|access[-_]?token|auth[-_]?token|oauth2[-_]?bearer|password|passwd|secret|client[-_]?secret|private[-_]?key|userpwd)(?:=|\s+)["']?)([^\s'";|]+)/gi,
    "CREDENTIAL",
  )
  // `date -u '+%H:%M'` shares the `-u x:y` shape; user names carry no % + =.
  replaceValue(/((?:--user(?:=|\s+)|\s-u\s+)"[^:"%+=]+:)((?:\\.|[^"\\])*)/gi, "PASSWORD")
  replaceValue(/((?:--user(?:=|\s+)|\s-u\s+)'[^:'%+=]+:)((?:\\.|[^'\\])*)/gi, "PASSWORD")
  replaceValue(/(--user(?:=|\s+)["']?[^:\s'";|]+:)([^\s'";|]+)/gi, "PASSWORD")
  replaceValue(/(\s-u\s+["']?[^:\s'";|%+=]+:)([^\s'";|]+)/gi, "PASSWORD")
  replaceValue(
    /((?:\b(?:docker|podman)\s+login[^\n;|&]*\s-p\s+|\bredis-cli[^\n;|&]*\s-a\s+|\b(?:mysql|mariadb)[^\n;|&]*\s-p)")((?:\\.|[^"\\])*)/gi,
    "PASSWORD",
  )
  replaceValue(
    /((?:\b(?:docker|podman)\s+login[^\n;|&]*\s-p\s+|\bredis-cli[^\n;|&]*\s-a\s+|\b(?:mysql|mariadb)[^\n;|&]*\s-p)')((?:\\.|[^'\\])*)/gi,
    "PASSWORD",
  )
  replaceValue(/(\b(?:docker|podman)\s+login[^\n;|&]*\s-p\s+["']?)([^\s'";|]+)/gi, "PASSWORD")
  replaceValue(/(\bredis-cli[^\n;|&]*\s-a\s+["']?)([^\s'";|]+)/gi, "PASSWORD")
  replaceValue(/(\b(?:mysql|mariadb)[^\n;|&]*\s-p)([^\s'";|]+)/gi, "PASSWORD")
  replaceValue(
    /((?:["']?(?:[A-Za-z_][A-Za-z0-9_.-]{0,63})?(?:api[_-]?key|access[_-]?key|token|secret|password|passwd|credential|private[_-]?key)[A-Za-z0-9_.-]{0,63}["']?)\s*(?:=|:)\s*")((?:\\.|[^"\\\n])*)(?=")/gi,
    "CREDENTIAL",
    (prefix, _secret, before) => opensQuote(before + prefix, '"'),
  )
  replaceValue(
    /((?:["']?(?:[A-Za-z_][A-Za-z0-9_.-]{0,63})?(?:api[_-]?key|access[_-]?key|token|secret|password|passwd|credential|private[_-]?key)[A-Za-z0-9_.-]{0,63}["']?)\s*(?:=|:)\s*')((?:\\.|[^'\\\n])*)(?=')/gi,
    "CREDENTIAL",
    (prefix, _secret, before) => opensQuote(before + prefix, "'"),
  )
  // YAML plain scalars can contain spaces. Mask the whole value, not just its
  // first word, while leaving ordinary type annotations untouched.
  replaceValue(
    /(^[ \t]*(?:["']?(?:[A-Za-z_][A-Za-z0-9_.-]{0,63})?(?:api[_-]?key|access[_-]?key|token|secret|password|passwd|credential|private[_-]?key)[A-Za-z0-9_.-]{0,63}["']?)[ \t]*:[ \t]*)([^\n#]+)/gim,
    "CREDENTIAL",
    (_prefix, secret) =>
      !/^(?:string|number|boolean|int|float|str|bool|bytes|any|unknown|object|none|null|undefined|true|false)\s*[;,}]?$/i.test(
        secret.trim(),
      ),
  )
  replaceValue(
    // The value shares the key's line; `serviceAccountToken:` followed by an
    // indented `path: token` is a YAML mapping, not a value.
    /((?:["']?(?:[A-Za-z_][A-Za-z0-9_.-]{0,63})?(?:api[_-]?key|access[_-]?key|token|secret|password|passwd|credential|private[_-]?key)[A-Za-z0-9_.-]{0,63}["']?)[ \t]*(?:=|:)[ \t]*["']?)([^\s'"`;|&,}]+)/gi,
    "CREDENTIAL",
    (prefix, secret) =>
      // A value with no letters or digits ("=== ClusterSecretStore ===") is
      // punctuation, not a credential.
      /[A-Za-z0-9]/.test(secret) &&
      // An expression such as jq's `nextPageToken:(.nextPageToken//null)` or a
      // `$TOKEN` reference names where a value comes from; it is not a value.
      !/^[(.$[]/.test(secret) &&
      // Prose such as "needs the dev-scoped token: the adapter reads ..."
      !/^(?:the|a|an|it|its|this|that|these|those|is|are|was|and|or|to|in|on|for|with|from|see|use|via|per|not|none|each|any|same)$/i.test(
        secret,
      ) &&
      !/(?:count|length|size|max|min|timeout|ttl)["']?\s*(?:=|:)/i.test(prefix) &&
      !(
        !/["']\s*$/.test(prefix) &&
        // Prose closes around the value: `automountServiceAccountToken: false).`
        /^(?:string|number|boolean|int|float|str|bool|bytes|any|unknown|object|none|null|undefined|true|false)[)\].:!?]*$/i.test(
          secret,
        )
      ),
  )
  replaceFull(new RegExp(providerToken.source, "g"), "TOKEN")
  replaceFull(new RegExp(jwt.source, "g"), "JWT")
  value = value.replace(/[\u200B-\u200F\uFEFF\u{E0000}-\u{E007F}]/gu, () => {
    kinds.add("INVISIBLE_CONTROL")
    return ""
  })
  for (const found of value.matchAll(/\[REDACTED:([A-Z_]+)\]/g)) kinds.add(found[1])

  // A detector that still sees a credential after replacement means this
  // review copy is not safe to send. The marker is shortened only for this
  // check, so it cannot satisfy a credential-value regex itself.
  const unmasked = value.replace(markerPattern, "x")
  return {
    value,
    kinds: [...kinds],
    complete: !residualCredential.test(unmasked),
  }
}

export function sanitizeReviewValue<T>(input: T): RedactionResult<T> {
  const kinds = new Set<string>()
  let complete = true
  const walk = (value: unknown, depth: number): unknown => {
    if (depth > 12) {
      complete = false
      return null
    }
    if (typeof value === "string") {
      const result = sanitizeText(value)
      result.kinds.forEach((kind) => kinds.add(kind))
      complete &&= result.complete
      return result.value
    }
    if (Array.isArray(value)) return value.map((item) => walk(item, depth + 1))
    if (value && typeof value === "object") {
      const out: Record<string, unknown> = {}
      for (const [key, item] of Object.entries(value)) {
        const safeKey = sanitizeText(key)
        if (safeKey.value !== key || !safeKey.complete) complete = false
        out[key] = walk(item, depth + 1)
      }
      return out
    }
    return value
  }
  return { value: walk(input, 0) as T, kinds: [...kinds], complete }
}

export const sanitizeReviewText = sanitizeText
