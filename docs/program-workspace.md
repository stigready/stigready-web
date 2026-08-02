# StigReady program workspace (this repo)

**stigready-web** is the GitHub Pages site for [stigready.com](https://stigready.com). Catalog
data is **not** hand-edited here for routine releases.

| Data | Source of truth | How it updates |
|------|-----------------|----------------|
| `catalog.json` | `stigready/stigready` → `public/catalog.json` | Factory `publish-site-catalog.sh` / program `publish_public_truth` → PR to this repo |
| `stigforge-factory.json` | Factory `public/stigforge-factory.json` | Same pipeline |

**Open the full program** (factory + StigForge + this site) in one Cursor session:

- Design: [stigready multi-repo-agent-workspace.md](https://github.com/stigready/stigready/blob/main/docs/how-to/multi-repo-agent-workspace.md)
- Bootstrap chat prompt: [program-workspace-bootstrap.md](https://github.com/stigready/stigready/blob/main/docs/prompts/program-workspace-bootstrap.md)

**Status:** [program-daily/latest.md](https://github.com/stigready/stigready/blob/main/docs/reports/program-daily/latest.md)
(site staleness vs factory `public/`).

Site-only rules: [.cursor/rules/stigready-brand-seo.mdc](../.cursor/rules/stigready-brand-seo.mdc) ·
[data contract](stigforge-factory-json.md).
