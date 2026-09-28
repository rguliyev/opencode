# Local permission-gate plugins

This directory tracks the source of the separately installed OpenCode
permission plugins. It is intentionally **not** under `.opencode/plugins/`:
putting another copy there would load two gates in this repository's sessions.

The files map to the user's OpenCode configuration as follows:

| Source                         | Installation target                                  |
| ------------------------------ | ---------------------------------------------------- |
| `plugins/command-approval.ts`  | `~/.config/opencode/plugins/command-approval.ts`     |
| `plugins/gcp-project-scope.ts` | `~/.config/opencode/plugins/gcp-project-scope.ts`    |
| `lib/aws-scope.ts`             | `~/.config/opencode/lib/aws-scope.ts`                |
| `lib/gcp-scope.ts`             | `~/.config/opencode/lib/gcp-scope.ts`                |
| `lib/permission-redaction.ts`  | `~/.config/opencode/lib/permission-redaction.ts`     |
| `kev/score_worker.py`          | Source for a separately managed Kev v2 socket worker |

The staged gate consults Jev through OpenRouter for Bash commands and other
permission-checked actions. It sends every reviewable Bash or non-Bash action
to the versioned local Kev v2 socket **before** Jev. Kev never grants
permission. The available checkpoint was trained only on shell commands and
scripts; the v2 worker accepts full sanitized task/action context but returns
`unsupported_action` for non-Bash rather than an uncalibrated probability.
Contextual Bash scores are marked `shell_only_unvalidated_context` and remain
advisory. The checkpoint's native 384-token state window can reject longer
context; the worker reports `context_status: model_overflow` while preserving
any usable shell-only baseline. The worker never logs or persists raw request
text. A reviewable Jev escalation or local blocking reason proceeds to GPT-6
Luna through OpenCode's configured `small_model` (`openai/gpt-6-luna`),
including high-risk and high-confidence Jev results. The core uses its
configured OpenAI OAuth access for a one-shot, tool-free structured review;
the plugin has no OpenRouter or API-key fallback for Luna and creates no
reviewer session.
Custom `tool_call` dispatches carry their available tool description and
arguments to Luna and always reach it, even when Jev allows. A description is
not proof of effects: automatic approval requires a core-attested npm origin
and pinned digests of the known goal-plugin source and package manifest, plus
the core-resolved entrypoint. The verified goal status
tools may initialize and persist local state on first use; resume and block
change local goal state. Unknown or changed custom tools still ask the human.
For grep, the regex expression is separate from the lexically resolved
requested path; symlinks and matched files are explicitly unverified until the
tool's later external-directory check and search. Any
request that would otherwise prompt the human gets a Luna attempt first. If
the action or task context cannot be shared safely, Luna receives only a
minimal withheld-evidence notice and must ask; raw sensitive evidence is not
sent. Luna's `allow` resolves ordinary Bash and non-Bash escalations; its
`ask` prompts the human. Jev scores are signals, not a veto on Luna.
Luna may treat a worker restart in an existing, directly human-identified E2B
test sandbox as part of an ongoing authorized test, including ordinary use of
the task's existing environment credentials. A different sandbox, materially
unknown remote effects, credential disclosure, or live/shared-state changes
still require human review; local human-only rules remain binding.
Luna gets an eight-second deadline per request. A timeout or malformed reply is
retried once with a fresh deadline; a second failure asks the human. A
reply grants permission only after strict model identity, shape, and reason
validation; errors or malformed replies never grant permission.
Configured denials, concrete local human-only rules, unreviewable or unsafe
context, model failures, and read-only reviewer restrictions still block
automatic approval. When a local eligibility check overrides Luna's `allow`,
the prompt names that condition and the audit record uses engine `local_veto`. Task evidence must match a trusted foreground built-in call; a
verified glob snapshot must stay in the workdir and contain no sensitive
filenames. Only the match count—not discovered filenames—is sent to Jev or
Luna. A verified built-in skill load sends its name, location, description,
content size, and digest—not its instruction body. Commands quoted in that
body are not treated as commands being run now; actual later commands are
reviewed separately. Credential-like literals and sensitive skill paths
still require human review. These local checks are not proof that every auth,
security, production, or regulated-data change is safe; Luna must ask on such
changes. Only
sanitized review copies leave the
process; executed arguments are not modified. The gate requires matching
OpenCode permission hooks and a local configuration with the expected hard-deny
patterns.
The gate verifies every parent session through the root, then reads only that
root session's user rows from OpenCode's local SQLite database in read-only
mode. This avoids hydrating thousands of assistant replies and oversized tool
results through the message API; bounded API paging remains a fallback if the
session is not in a local database. At most 512 user messages and 96 KiB of
sanitized timeline are sent, with message IDs and times. Non-text attachments
are never sent; redacted literals and omitted attachments are marked and
cannot themselves authorize an action. A short "continue" can refer to the
still-applicable original task, while later constraints or revocations remain
visible. New slash-command template text, and direct text modified or inserted
by a `chat.message` hook, are marked synthetic after the hook and represented
only by non-authorizing markers. A latest such message therefore requires human
review rather than silently reusing a previous task.
Legacy unmarked command-expanded messages cannot be proven direct-human from
the historical database alone. Synthetic and compaction-replayed prompts are
not human authorization.
If lineage, history, or safe redaction is incomplete, the gate asks rather than
silently dropping intervening messages or promoting a child task to human
authority. History is reread for each review so edits to older messages cannot
leave a stale authorization cache. The size limits bound review latency and
disclosure; oversized histories still require human review.
For subagents, Kev, Jev, and Luna receive the latest agent-written delegated
task, explicitly labeled as context rather than human authorization. A
credential-like literal is redacted in that task rather than causing the
entire task to disappear; the marker cannot authorize an action. Email, phone,
and SSN identifiers in human messages and delegated tasks are likewise masked
in place; words such as "PII" or "patient" are not withheld. Missing,
synthetic, non-text, oversized, or unsafe-to-redact delegated tasks still cause
the gate to ask Luna using minimal safe context before prompting the human.
Deployment-specific paths are present in the source; review and adapt them
before installing elsewhere.

The OpenCode tool dispatcher requests `tool_call` permission for every tool.
The plugin defers trusted built-ins to their richer internal permission check;
custom and otherwise ungated tools are reviewed at dispatch. Synthetic task
calls use the same path. Without the plugin, the default is a human prompt.

No credentials, scope policy files, kill-switch value, decision logs, Kev
checkpoint, training corpus, calibration state, or worker service configuration
are tracked here. `kev/score_worker.py` requires `KEV_REPO`, `KEV_CHECKPOINT`,
`KEV_QUESTIONS`, and `KEV_SCORE_SOCKET` at startup. Source presence alone does
not imply a deployed worker. Deploy the v2 worker and matching plugin together
only with human approval. The checkpoint still requires a curated,
human-adjudicated non-Bash training set and held-out validation before its
action scores can be trusted. Copying plugin sources does not activate them in
an already-running OpenCode server; a controlled server reload is required.

## macOS client package

`macos/install.sh` is the installer for a future matching macOS package. It
selects `bin/darwin-arm64/opencode` or `bin/darwin-x64/opencode`, verifies its
entry in `SHA256SUMS`, backs up the current executable, and installs atomically
to `~/src/bin/opencode` as requested. Merely adding this script does not build
or install a client binary.
