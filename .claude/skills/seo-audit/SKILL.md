---
name: seo-audit
description: >-
  Audit stigready.com HTML for SEO and trust: title, description, canonical, OG/Twitter,
  JSON-LD, sitemap coverage, GA tag, internal links, and brand guardrails (no private
  stigforge monorepo, no fake Coming soon). Use when asked for an SEO review, pre-launch
  check, sitemap fix, or after adding pages under blog/ or applied/.
---

# SEO audit (stigready-web)

Read-only first; then fix gaps the user wants fixed. Scope is this static GitHub Pages site.

## Pages to cover

- `/` → [index.html](../../../index.html)
- `/applied/` → [applied/index.html](../../../applied/index.html)
- `/blog/` → [blog/index.html](../../../blog/index.html)
- Every `blog/*.html` post
- [sitemap.xml](../../../sitemap.xml), [robots.txt](../../../robots.txt)

## Checklist (per HTML page)

| Check | Expect |
|---|---|
| `<title>` | Unique, brand + topic |
| `meta name="description"` | Unique, ≤~160 chars, no “coming soon” filler |
| `link rel="canonical"` | Absolute `https://stigready.com/...` |
| `og:url` / `og:title` / `og:description` / `og:image` | Present; image `https://stigready.com/assets/logo.png` |
| Twitter card | `summary` + title/description/image |
| JSON-LD | Organization/WebSite on home; BlogPosting on posts; WebPage elsewhere |
| GA | `G-R2J9HMP1XX` gtag present |
| Favicon | `/assets/logo.png` |
| Nav | Base, Applied, StigForge, Blog, Pricing, Contact (same as home) |

## Site-wide

1. **Sitemap** — every public HTML URL listed; no dead paths; blog posts included when published.
2. **robots.txt** — allows `/` and points at sitemap.
3. **Private monorepo** — `rg` for `github.com/stigready/stigforge` (must not appear as a public CTA). Role repos `*-cis` / `*-stig` are OK.
4. **Coming soon** — no Marketplace “Coming soon” status UI; don’t reintroduce listing-state badges.
5. **Logo contrast** — site uses dark-bg logo (`assets/logo.png` / `logo.svg` with white STIG). Light-bg variant is `logo-on-light.*` for Marketplace only.
6. **Internal links** — from blog to `/#stigforge`, `/#base-tier`, seller profile, public role repos.

## Output format

```markdown
## SEO audit — stigready-web
### Pass
- ...
### Fail / fix
- path — issue — suggested fix
### Sitemap gaps
- ...
```

Then offer to patch Fail items and open a PR if the user wants.
