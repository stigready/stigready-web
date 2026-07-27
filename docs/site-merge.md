# Unified StigReady web

- **stigready.com** — `index.html` (base AMIs) + `#ansible-roles` catalog
- **StigApplied** — `stigapplied.html` (merged from `stigapplied-web` repo)
- **DNS:** point `stigapplied.com` at GitHub Pages with a redirect to `https://stigready.com/stigapplied.html` when ready (or keep separate CNAME until cutover).

Role repo links use org **`stigready`** per StigForge `release/registry.yml`.
