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
advisory. The worker never logs or persists raw request text. A Jev escalation
without a local blocking rule can proceed to GPT-6 Luna via OpenRouter. Luna
may auto-allow only a root-session, core-verified built-in `glob` operation for
one literal file path in the local workdir. The built-in supplies a bounded
filename snapshot for local checks, but only the match count—not discovered
filenames—is sent to Jev or Luna. Wildcard discovery and sensitive-looking
filenames stay with the human. Auto-allow also requires a safely retrieved
latest human request, a valid
low-confidence Jev verdict, and no Jev risk over its existing human-review
threshold. For Bash, edits, remote tools, and other actions, Luna is advisory:
its `allow` cannot replace human approval, but its verdict is shown in the
human prompt. This restriction is intentional:
edits can run project formatters without a second permission check, while the
current static rules cannot prove every human-only auth, security, production,
or regulated-data gate absent from arbitrary commands and tools. High-confidence
Jev denials, model failures, malformed Luna output, missing context, and local
blocking rules still ask the human. Only sanitized review copies leave the
process; executed arguments are not modified. The gate requires matching
OpenCode permission hooks and a local configuration with the expected hard-deny
patterns.
The gate pages through bounded session-message responses to find the latest
root-session human request even when recent assistant tool results are large.
For subagents, Kev, Jev, and Luna receive the latest agent-written delegated
task, explicitly labeled as context rather than human authorization. If either
required task context is unavailable or contains an obvious credential or
personal-data marker, the gate skips automatic model review and asks the human.
Deployment-specific paths are present in the source; review and adapt them
before installing elsewhere.

The OpenCode tool dispatcher requests `tool_call` permission for every tool.
The plugin defers trusted built-ins to their richer internal permission check;
custom and otherwise ungated tools are reviewed at dispatch. Synthetic task
calls use the same path. Without the plugin, the default is a human prompt.

No credentials, scope policy files, kill-switch value, decision logs, Kev
checkpoint, training corpus, calibration state, or worker service configuration
are tracked here. `kev/score_worker.py` requires `KEV_REPO`, `KEV_CHECKPOINT`,
`KEV_QUESTIONS`, and `KEV_SCORE_SOCKET` at startup. It is **not installed or
running** merely because its source exists here; the current live socket still
speaks the older protocol. Deploy the v2 worker and matching plugin together
only with separate human approval. The checkpoint still requires a curated,
human-adjudicated non-Bash training set and held-out validation before its
action scores can be trusted. Copying plugin sources does not activate them in
an already-running OpenCode server; a controlled server reload is required.

## macOS client package

`macos/install.sh` is the installer for a future matching macOS package. It
selects `bin/darwin-arm64/opencode` or `bin/darwin-x64/opencode`, verifies its
entry in `SHA256SUMS`, backs up the current executable, and installs atomically
to `~/src/bin/opencode` as requested. Merely adding this script does not build
or install a client binary.
