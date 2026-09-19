# This directory is generated

Every agent, skill and rule below is **authored in the `claude-agents` repo** under
`config/`, and vendored here by `scripts/sync-agent-config.sh`.

**Do not edit these files here.** A downstream edit is drift: it is not the version any
other repo or session sees, and the `agent-config-in-sync` CINC control fails the build
on it. Change `claude-agents/config/<...>`, run `sync-agent-config.sh --write`, and open
one PR carrying both sides.

What this repo receives is set by `claude-agents/config/manifest.yml`.
