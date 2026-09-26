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
| `lib/permission-redaction.ts` | `~/.config/opencode/lib/permission-redaction.ts` |

The gate consults Jev through OpenRouter for Bash commands and other
permission-checked actions. It sends advisory scores to a local Kev socket;
Kev's current model is command-trained, so non-Bash scores are uncalibrated
and never grant permission. It requires matching OpenCode permission hooks and a local
configuration with the expected hard-deny patterns. Deployment-specific paths
are present in the source; review and adapt them before installing elsewhere.

The OpenCode tool dispatcher requests `tool_call` permission for every tool.
The plugin defers trusted built-ins to their richer internal permission check;
custom and otherwise ungated tools are reviewed at dispatch. Synthetic task
calls use the same path. Without the plugin, the default is a human prompt.

No credentials, scope policy files, kill-switch value, decision logs, Kev model
state, or worker runtime files are tracked here. Copying these sources does not
activate them in an already-running OpenCode server; a controlled server reload
is required after changing an installed plugin.
