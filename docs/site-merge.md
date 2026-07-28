# Unified StigReady web

**One domain:** [stigready.com](https://stigready.com) only.

| Path | Content |
|------|---------|
| `/` | StigReady Base + catalog (`catalog.json`) |
| `/applied/` | StigReady Applied (previously “StigApplied” tier) |
| `stigapplied.html` | Optional same-host redirect → `/applied/` (`noindex`) for old bookmarks |

## Abandoned

- **`stigapplied.com`** — not maintained; no DNS redirect project.
- **`stigapplied-web`** repo — **archived** on GitHub; do not restore Pages or CNAME.

Applied AMI marketing, scores, and catalog filters belong on **stigready.com** under `/applied/` and
the main catalog — single StigReady brand.

## Catalog sync

Copy from the factory with `publish-catalog.py --to-site` — do not hand-edit OS/arch rows.
StigForge / role-repo links on the site only when those repos are public and approved.
