# Subscription-first paid fallback

OpenAI and Anthropic OAuth plugin fetches are wrapped by
`packages/opencode/src/provider/subscription-fallback.ts`. Existing subscription
credentials remain authoritative and are never overwritten by paid credentials.

## Explicit opt-in credentials

Store these **separate** records in the existing private OpenCode `data/auth.json`
using the normal auth API or a protected credential installer:

- `openai-fallback`: OAuth-shaped workspace access token (`access: "at-…"`,
  `refresh: ""`, `expires: <nonnegative integer>`). This uses the Codex endpoint,
  not the platform API, without inheriting the subscription workspace header.
- `anthropic-fallback`: API credential (`type: "api"`, `key: "…"`). This uses
  Anthropic's Messages API without the OAuth authorization or OAuth beta header.

Never put real secrets in source, model configuration, logs, or these examples.
Removing the fallback record disables fallback on the next request. No paid
credential is discovered automatically from unrelated providers or environments.
API-key-only primary authentication is unchanged.

## Switching and warnings

Only a pre-stream HTTP 429 with an explicit subscription quota signal enables
fallback: OpenAI `usage_limit_reached`; Anthropic `rate_limit_error` with a rejected
unified subscription status/window. Generic RPM/TPM 429s, 400/401/403, server
errors, network failures, and errors after streaming starts do not trigger paid
replay. OpenAI's WebSocket adapter exposes pre-stream quota failures as HTTP 429.
Custom base URLs and non-replayable request bodies are not automatically retried.

On quota exhaustion the original request is retried once with paid credentials.
Quota cooldown is model-scoped and capped at 60 seconds (or the reported reset if
sooner). The next request after cooldown tries the subscription again. This also
picks up manually restored limits without restarting OpenCode. Requests are not
sent merely to poll allowance; idle sessions consume nothing.

30-second warning toasts and server logs report:

- Usage at or above 90%, when provided by response headers.
- Switching to **PAID** fallback, known reset time, and advice to check/reset
  limits in the provider dashboard.
- Missing fallback credentials or failure of the paid request.
- Return to subscription after successful recovery.

Warnings are throttled per model/session to one per five minutes; new sessions
receive their own warning. No limits, billing settings, or overage settings are
changed automatically. Model cost display is not an authoritative paid invoice.

## Verification

From `packages/opencode`:

```sh
bun test --timeout 30000 test/provider/subscription-fallback.test.ts test/provider/subscription-fallback-notice.test.ts test/plugin/codex.test.ts test/plugin/openai-ws.test.ts test/plugin/auth-override.test.ts test/provider/provider.test.ts
bun run typecheck
```

Tests cover primary success, quota failover/recovery, strict error classification,
credential removal/change, aborts, model isolation, warnings, HTTP transports,
OpenAI WebSocket quota errors, payload/header isolation, and paid failure without
recursive fallback. These tests never send real paid model requests.
