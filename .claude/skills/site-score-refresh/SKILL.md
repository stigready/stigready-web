---
name: site-score-refresh
description: >-
  Refresh stigready-web catalog.json and/or stigforge-factory.json from AWS AMIs and
  factory verify artifacts, then open a PR when scores or cells drift. Use after a
  build run, when Applied/Factory scores look wrong, or when asked to sync the site
  data from source of truth.
---

# Site score / catalog refresh

Keep published scores and catalog rows honest. Prefer regenerate over hand-edit.

## Sources of truth

| Data | Source | Site file |
|---|---|---|
| Base + Applied product rows / Applied scores | `stigready` `scripts/publish-catalog.py --to-site ../stigready-web` (AWS AMIs + tags) | [catalog.json](../../../catalog.json) |
| StigForge role scores | `stigforge` `scripts/publish-stigforge-factory-json.py ../stigready-web/stigforge-factory.json` (prefer gate-passing artifacts, including nested `verify-<role>/`) | [stigforge-factory.json](../../../stigforge-factory.json) |
| Base OS/arch existence | [ami-site-sync](../ami-site-sync/SKILL.md) | catalog / Base table |

## Steps

1. Confirm which surface drifted (Applied table, Factory scores, Base rows).
2. Regenerate from the commands above (need sibling checkouts of `stigready` / `stigforge` as appropriate).
3. Diff — call out new cells (e.g. new arch/profile) and score changes.
4. Do **not** hand-edit OS/arch/score rows if a publisher exists.
5. Branch + PR summarizing what changed. Merge only if asked.
6. Optional: run **seo-audit** if HTML changed; otherwise JSON-only is enough.

## Guardrails

- No AMI IDs on the site.
- No private monorepo links.
- Factory publisher must not publish sub-floor scores when a gate-passing artifact exists.
