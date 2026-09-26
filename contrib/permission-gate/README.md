# Local permission-gate plugins

This directory tracks the source of the separately installed OpenCode
permission plugins. It is intentionally **not** under `.opencode/plugins/`:
putting another copy there would load two gates in this repository's sessions.

The files map to the user's OpenCode configuration as follows:

| Source                         | Installation target                               |
| ------------------------------ | ------------------------------------------------- |
| `plugins/command-approval.ts`  | `~/.config/opencode/plugins/command-approval.ts`  |
| `plugins/gcp-project-scope.ts` | `~/.config/opencode/plugins/gcp-project-scope.ts` |
| `lib/aws-scope.ts`             | `~/.config/opencode/lib/aws-scope.ts`             |
| `lib/gcp-scope.ts`             | `~/.config/opencode/lib/gcp-scope.ts`             |
| `lib/permission-redaction.ts`  | `~/.config/opencode/lib/permission-redaction.ts`  |

The gate consults Jev through OpenRouter for Bash commands and other
permission-checked actions. It sends Bash commands to a local Kev socket for
advisory scoring. The current Kev checkpoint was trained only on shell commands:
non-Bash actions are marked `unsupported_action` and are not sent to Kev.
Kev never grants permission. For Bash, the gate awaits Kev before Jev; for
non-Bash it records Kev as unsupported and proceeds to Jev. A Jev escalation
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
For subagents, Jev also receives the latest agent-written delegated task,
explicitly labeled as context rather than human authorization; the current Kev
worker's older schema cannot accept these two additional fields yet. If either
required task context is unavailable or contains an obvious credential or
personal-data marker, the gate skips automatic model review and asks the human.
Deployment-specific paths are present in the source; review and adapt them
before installing elsewhere.

The OpenCode tool dispatcher requests `tool_call` permission for every tool.
The plugin defers trusted built-ins to their richer internal permission check;
custom and otherwise ungated tools are reviewed at dispatch. Synthetic task
calls use the same path. Without the plugin, the default is a human prompt.

No credentials, scope policy files, kill-switch value, decision logs, Kev model
state, or worker runtime files are tracked here. Copying these sources does not
activate them in an already-running OpenCode server; a controlled server reload
is required after changing an installed plugin.

## macOS client package

`macos/install.sh` is the installer for a future matching macOS package. It
selects `bin/darwin-arm64/opencode` or `bin/darwin-x64/opencode`, verifies its
entry in `SHA256SUMS`, backs up the current executable, and installs atomically
to `~/src/bin/opencode` as requested. Merely adding this script does not build
or install a client binary.
