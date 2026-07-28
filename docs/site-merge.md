# Unified StigReady web

One brand, two product tiers on **stigready.com**:

- **`/`** — StigReady Base + StigReady Applied (catalog-driven from `catalog.json`)
- **`/applied/`** — Applied landing (SEO target for the former StigApplied brand)
- **`stigapplied.html`** — `noindex` redirect → `/applied/`

**DNS:** 301 `stigapplied.com` → `https://stigready.com/applied/` (keep the domain registered).

**Catalog:** copy from the factory with `publish-catalog.py --to-site` — do not hand-edit OS/arch rows. StigForge / role-repo links are not published on the site until those repos are ready.
