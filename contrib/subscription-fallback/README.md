# Subscription-first fallback: external auth plugins

No provider-core patch, new hook, auth-store migration, or global fetch override.
These **external** plugins compose the existing OpenAI Codex auth implementation
from this source revision and the installed, pinned
`@ex-machina/opencode-anthropic-auth@1.8.6`. Auth methods, refresh handling,
request transformations, OpenAI WebSockets and stream decoding remain theirs.
The build bundles those implementations; deployment needs no new npm package.

## Existing capability review (2026-10-14)

- Installed and npm-latest Ex Machina **1.8.6** has OAuth refresh/retry, but only
  one model-request fetch; it has no quota-triggered credential fallback.
- CortexKit Anthropic **2.0.1** implements quota-confirmed API-key fallback.
  It also brings account custody migration and unrelated model/relay/cache
  features. It is not necessary to replace the current login implementation.
- CortexKit OpenAI **1.0.3** implements multi-OAuth-account routing, not a
  drop-in route for this user's refresh-less `at-` Codex token: its released
  `jO` account parser marks empty refresh tokens corrupt; its legacy
  `getUsableFallbackAccounts` selects OAuth accounts only, and native pool
  `usableToken` also selects OAuth rows only. Merely seeing an API-key account
  type in shared code is not proof it can serve that route.
- Reviewed published npm tarballs against their registry SHA-512 integrities,
  not only README claims or unreleased GitHub main.

Sources: [Ex Machina](https://github.com/ex-machina-co/opencode-anthropic-auth),
[CortexKit OpenAI](https://github.com/cortexkit/openai-auth),
[CortexKit Anthropic](https://github.com/cortexkit/anthropic-auth).

## Anthropic native paid extra usage

The Claude OAuth account may already have extra usage enabled. No separate API
key is needed for this provider-managed path, and an HTTP 200 response can be
paid. The plugin now observes the successful response headers before returning
its stream, without sending another request or changing credentials:

- Explicit `anthropic-ratelimit-unified-overage-in-use: true`, OR unified status
  `rejected` plus overage status `allowed` / `allowed_warning`, signals paid extra
  usage. This matches the installed Anthropic Claude Code **2.1.284** parser.
- Overage `allowed` alone only means eligible, **not** that the request is paid.
  Representative claim alone is not treated as proof of paid usage either.
- Warn through toast and server log when paid extra usage is reported. Deduplicate
  per session/model, warn again on reentry, and announce a return to included
  usage only on an explicit included-status response. Missing headers are unknown.
- Warn near the included limit (90% utilization or provider `allowed_warning`)
  and explain the native extra-usage path instead of claiming an API key is needed.
- On an actual quota rejection with rejected overage, direct the user to Claude
  Settings > Usage to check balance, limits and enablement; do not auto-purchase
  credits, alter limits, or claim an unsuccessful request was billed.

The paid warning arrives with response headers: it cannot retroactively prevent
charges on that first request. The near-limit warning provides advance notice
when Anthropic supplies the relevant telemetry. No usage polling or background
model requests are added. Real billing/exhaustion is not forced in tests.

[Anthropic's explanation of usage credits](https://support.claude.com/en/articles/12429409-manage-usage-credits-for-paid-claude-plans)
confirms continuation on the existing subscription account when funded/enabled.

## Behavior

- Subscription first. At 90% usage, warn when the provider supplies usage headers.
- Switch only on explicit subscription exhaustion: OpenAI HTTP 429 with
  `usage_limit_reached`; Anthropic HTTP 429 `rate_limit_error` with a rejected
  subscription-window header. Generic throttles, auth failures, network errors,
  and server errors do not authorize paid usage.
- Warn **before** the paid request through the existing TUI toast API and server
  log. Warn on missing/failed fallback and on subscription recovery. Show reset
  time if supplied; never purchase/reset credits automatically.
- Retry subscription within 60 seconds while requests continue, so a manual
  allowance reset is recognized. No background generation or keep-warm spending.
- OpenAI PAT goes to Codex, not the platform API; remove subscription workspace
  and residency headers. Anthropic API key uses the original SDK body, without
  OAuth request/tool-name rewriting or OAuth-only headers.
- Never replay after a response stream has started. A pre-stream WebSocket quota
  rejection can fall back; an error inside a started stream is returned normally.
- Only replayable JSON POSTs to the exact standard provider endpoints qualify.
  Custom endpoints, streamed request bodies, and API-key-only primary auth pass
  through. At most one paid attempt per request.
- The sidecar is reread each request, must be private (no group/other access),
  and is never written by the plugins. Missing/invalid credentials fail closed
  for paid use without blocking successful subscription requests.
- Existing OAuth model dollar-cost estimates remain zero; they do not measure
  paid-route billing. Provider billing is authoritative.

## Build and configuration

From `packages/opencode`, using existing dependencies only:

```sh
ANTHROPIC_PLUGIN_DIR=/absolute/path/to/existing/ex-machina-package \
PLUGIN_OUTDIR=/absolute/task/output/directory \
bun run ../../contrib/subscription-fallback/build.ts
```

The manifest records the source revision, version and artifact SHA-256 hashes.
Rebuild these bundles after changing the source Codex auth implementation.

Replace the existing Anthropic plugin entry with the wrapper; do not load both
Anthropic plugins. Add the OpenAI wrapper (external auth overrides built-in
auth). Do not put helpers or credential files in auto-discovered `plugins/`:

```json
{
  "plugin": [
    [
      "file:///data/rguliyev/.opencode/lib/subscription-fallback/anthropic.js",
      {
        "credentials": "/data/rguliyev/opencode/data/subscription-fallback.json"
      }
    ],
    [
      "file:///data/rguliyev/.opencode/lib/subscription-fallback/openai.js",
      {
        "credentials": "/data/rguliyev/opencode/data/subscription-fallback.json"
      }
    ]
  ]
}
```

The mode-0600 sidecar accepts `openai-fallback` as an OAuth-shaped record with
`access` holding the existing Codex PAT, empty `refresh`, and optional `expires`;
`anthropic-fallback` is an API record with `key`. Never commit real values.
Leave Anthropic fallback absent when using native Claude extra usage. A separate
API key is only needed for the optional separate-credential fallback route.

Back up and preserve native `auth.json` subscription entries. Explicit approval
is required for protected config installation. Config activation requires a
server restart; installation does not authorize one. Roll back by restoring the
previous config and removing wrapper entries, not by overwriting current OAuth
credentials with a potentially stale backup.

## Tests

From `packages/opencode`:

```sh
FALLBACK_PLUGIN_BUNDLES=/absolute/task/output/directory \
bun test test/plugin/subscription-fallback.test.ts test/plugin/subscription-fallback-plugin.test.ts
bun run typecheck
```

Also run `bun run typecheck` from this directory. Bundle tests execute the actual
packaged auth plugins against loopback HTTP using synthetic credentials, assert
warning-before-paid ordering, primary preservation, payload/header correctness
and credential-file immutability. Unit tests cover cooldown/recovery, two
providers, wrong endpoints, non-quota failures, abort, streamed errors, and a
real pre-stream OpenAI WebSocket quota rejection. No real paid request is needed.
