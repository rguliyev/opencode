// Redact review copies only. Never apply this to the arguments OpenCode executes.
export type RedactionResult<T> = {
  value: T
  kinds: string[]
  complete: boolean
}

const marker = (kind: string) => `[REDACTED:${kind}]`
const markerPattern = /\[REDACTED:[A-Z_]+\]/g
const reference = /^(?:\$|process\.env\b|os\.environ\b|os\.getenv\b|getenv\(|env\(|\[REDACTED:)/i

// This is deliberately a bounded, local detector rather than a claim that
// arbitrary passwords can be recognized. Unrecognized values remain a risk.
const residualCredential =
  /\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{25,}|(?:AKIA|ASIA)[A-Z0-9]{16}|ya29\.[A-Za-z0-9_-]{20,}|4\/0A[A-Za-z0-9_-]{20,}|1\/\/[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})\b|-----BEGIN [A-Z ]*PRIVATE KEY-----/i

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
    shouldRedact: (prefix: string, secret: string) => boolean = () => true,
  ) => {
    value = value.replace(pattern, (found, prefix: string, secret: string) => {
      if (!secret || reference.test(secret) || !shouldRedact(prefix, secret)) return found
      kinds.add(kind)
      return prefix + marker(kind)
    })
  }

  replaceFull(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "PRIVATE_KEY")
  replaceValue(/((?:https?:\/\/)?[^\s/:@]+:)([^\s/@]+)(?=@[^\s/]+)/gi, "PASSWORD")
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
  replaceValue(/((?:--user(?:=|\s+)|\s-u\s+)"[^:"]+:)((?:\\.|[^"\\])*)/gi, "PASSWORD")
  replaceValue(/((?:--user(?:=|\s+)|\s-u\s+)'[^:']+:)((?:\\.|[^'\\])*)/gi, "PASSWORD")
  replaceValue(/(--user(?:=|\s+)["']?[^:\s'";|]+:)([^\s'";|]+)/gi, "PASSWORD")
  replaceValue(/(\s-u\s+["']?[^:\s'";|]+:)([^\s'";|]+)/gi, "PASSWORD")
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
    /((?:["']?(?:[A-Za-z_][A-Za-z0-9_.-]*)?(?:api[_-]?key|access[_-]?key|token|secret|password|passwd|credential|private[_-]?key)[A-Za-z0-9_.-]*["']?)\s*(?:=|:)\s*")((?:\\.|[^"\\])*)/gi,
    "CREDENTIAL",
  )
  replaceValue(
    /((?:["']?(?:[A-Za-z_][A-Za-z0-9_.-]*)?(?:api[_-]?key|access[_-]?key|token|secret|password|passwd|credential|private[_-]?key)[A-Za-z0-9_.-]*["']?)\s*(?:=|:)\s*')((?:\\.|[^'\\])*)/gi,
    "CREDENTIAL",
  )
  // YAML plain scalars can contain spaces. Mask the whole value, not just its
  // first word, while leaving ordinary type annotations untouched.
  replaceValue(
    /(^[ \t]*(?:["']?(?:[A-Za-z_][A-Za-z0-9_.-]*)?(?:api[_-]?key|access[_-]?key|token|secret|password|passwd|credential|private[_-]?key)[A-Za-z0-9_.-]*["']?)[ \t]*:[ \t]*)([^\n#]+)/gim,
    "CREDENTIAL",
    (_prefix, secret) =>
      !/^(?:string|number|boolean|int|float|str|bool|bytes|any|unknown|object|none|null|undefined|true|false)\s*[;,}]?$/i.test(
        secret.trim(),
      ),
  )
  replaceValue(
    /((?:["']?(?:[A-Za-z_][A-Za-z0-9_.-]*)?(?:api[_-]?key|access[_-]?key|token|secret|password|passwd|credential|private[_-]?key)[A-Za-z0-9_.-]*["']?)\s*(?:=|:)\s*["']?)([^\s'"`;|&,}]+)/gi,
    "CREDENTIAL",
    (prefix, secret) =>
      !/(?:count|length|size|max|min|timeout|ttl)["']?\s*(?:=|:)/i.test(prefix) &&
      !(
        !/["']\s*$/.test(prefix) &&
        /^(?:string|number|boolean|int|float|str|bool|bytes|any|unknown|object|none|null|undefined|true|false)$/i.test(
          secret,
        )
      ),
  )
  replaceFull(
    /\b(?:sk-(?:proj|ant|live|test)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{25,}|(?:AKIA|ASIA)[A-Z0-9]{16}|ya29\.[A-Za-z0-9_-]{20,}|4\/0A[A-Za-z0-9_-]{20,}|1\/\/[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|pypi-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9_-]{20,}|sk_(?:live|test)_[A-Za-z0-9]{16,})\b/g,
    "TOKEN",
  )
  replaceFull(/\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, "JWT")
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
