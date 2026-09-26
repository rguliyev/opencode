# Local permission-gate plugins

This directory tracks the source of the separately installed OpenCode
permission plugins. It is intentionally **not** under `.opencode/plugins/`:
putting another copy there would load two gates in this repository's sessions.

The files map to the user's OpenCode configuration as follows:

| Source | Installation target |
| --- | --- |
| `plugins/command-approval.ts` | `~/.config/opencode/plugins/command-approval.ts` |
| `plugins/gcp-project-scope.ts` | `~/.config/opencode/plugins/gcp-project-scope.ts` |
| `lib/aws-scope.ts` | `~/.config/opencode/lib/aws-scope.ts` |
| `lib/gcp-scope.ts` | `~/.config/opencode/lib/gcp-scope.ts` |

The command gate consults Jev through OpenRouter and sends advisory scores to a
local Kev socket. It requires matching OpenCode permission hooks and a local
configuration with the expected hard-deny patterns. Deployment-specific paths
are present in the source; review and adapt them before installing elsewhere.

No credentials, scope policy files, kill-switch value, decision logs, Kev model
state, or worker runtime files are tracked here. Copying these sources does not
activate them in an already-running OpenCode server; a controlled server reload
is required after changing an installed plugin.
