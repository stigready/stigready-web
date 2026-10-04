---
name: site-score-refresh
description: >-
  Refresh stigready-web catalog.json from AWS AMIs and their tags, then open a PR when
  scores or cells drift. Use after a
  build run, when Applied/Factory scores look wrong, or when asked to sync the site
  data from source of truth.
---
<!-- GENERATED — DO NOT EDIT HERE.
     Authored in the claude-agents repo at config/skills/site-score-refresh/SKILL.md
     Vendored by scripts/sync-agent-config.sh. Edit it there and re-sync;
     an edit made in this repo is drift and fails the build. -->

# Site score / catalog refresh

Keep published scores and catalog rows honest. Prefer regenerate over hand-edit.

## Sources of truth

| Data | Source | Site file |
|---|---|---|
| Base + Applied product rows / Applied scores | `stigready` `scripts/publish-catalog.py --to-site ../stigready-web` (AWS AMIs + tags) | [catalog.json](https://github.com/stigready/stigready-web/blob/main/catalog.json) |
| StigForge role scores | **Do not refresh.** `stigforge` `scripts/publish-stigforge-factory-json.py` reads container-verify artifacts, which [0017](https://github.com/stigready/claude-agents/blob/main/design/decisions/0017-remove-container-verify.md) removed because they scored a fraction of the profile. No replacement source exists yet; a stale score here is backlog, not something to regenerate | [stigforge-factory.json](https://github.com/stigready/stigready-web/blob/main/stigforge-factory.json) |
| Base OS/arch existence | [ami-site-sync](https://github.com/stigready/claude-agents/blob/main/config/skills/ami-site-sync/SKILL.md) | catalog / Base table |

## Steps

1. Confirm which surface drifted (Applied table, Factory scores, Base rows).
2. Regenerate from the commands above (need sibling checkouts of `stigready` / `stigforge` as appropriate).
3. Diff — call out new cells (e.g. new arch/profile) and score changes.
4. Do **not** hand-edit OS/arch/score rows if a publisher exists.
5. Branch + PR in `stigready-web` summarizing what changed. Merge only on a green `validate`, and only if asked.
6. Optional: run **seo-audit** if HTML changed; otherwise JSON-only is enough.

## Guardrails

- No AMI IDs on the site.
- No private monorepo links.
- Scores come only from an AMI's OpenSCAP result (the build is the only oracle, 0017), and
  only from Q4 builds ([0035](https://github.com/stigready/claude-agents/blob/main/design/decisions/0035-2026q4-release-rebuild-everything.md)).
