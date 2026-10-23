# Subagent context defaults

Set `context_budget: default` in an agent's Markdown frontmatter to keep the
model's normal usable capacity and configured compaction headroom. Alternatively,
use an integer token count of at least 32000, e.g. `context_budget: 256000`.
The server clamps numeric budgets to the model's existing usable capacity.
This is an early-compaction threshold, not a larger model window or a hard
request-size limit.

The plugin applies numeric defaults on the first prompt for each child
session/model. It does not change parent sessions, disabled agents, permissions,
models, or provider context limits. Existing manual session/model selections win;
a later manual reset is not overwritten. Configuration changes affect previously
uninitialized session/model pairs, not already initialized ones.

Requires this fork's per-session budget implementation (`cdec78320c` or later).
Bundle `plugin.ts` for Bun into one JS file before installing under the protected
OpenCode `plugins` directory. No runtime dependencies are needed in the bundle.
Loading the plugin or edited agent configs requires a server restart; installation
does not restart the server. The agent setting is stripped from provider options.
