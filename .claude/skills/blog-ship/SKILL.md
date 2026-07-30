---
name: blog-ship
description: >-
  Ship the next StigReady Base + StigForge how-to from docs/blog-roadmap.md onto
  stigready.com/blog/. Drafts the HTML post, updates the published list and sitemap,
  removes the item from the maintainer roadmap, and opens a PR. Use when asked to
  write/publish a blog post, ship the next roadmap item, or keep the weekly content cadence.
---

# Blog ship (Base + StigForge)

Publish **one** how-to from the maintainer queue onto the public blog. The public site
shows **published posts only** — never render the roadmap on stigready.com.

## Source of truth

| Surface | Path |
|---|---|
| Queue (private) | [docs/blog-roadmap.md](../../../docs/blog-roadmap.md) |
| Public list | [blog/index.html](../../../blog/index.html) |
| Examples | [blog/rhel9-base-stigforge-stig.html](../../../blog/rhel9-base-stigforge-stig.html), [blog/ubuntu24-base-stigforge-cis.html](../../../blog/ubuntu24-base-stigforge-cis.html) |
| Sitemap | [sitemap.xml](../../../sitemap.xml) |

## Standing rules

- Link **public** role repos only (`stigready/*-cis`, `*-stig`).
- **Never** link `stigready/stigforge` (private monorepo).
- Pin Ansible to a **git tag** (resolve latest `v*` tag via `gh api repos/stigready/<repo>/tags`), never `main`.
- Marketplace CTA: `https://aws.amazon.com/marketplace/seller-profile?id=seller-h3qxnolnrqakk`
- Match **nav + footer** from [index.html](../../../index.html) / existing blog posts (Base, Applied, StigForge, Blog, Pricing, Contact).
- RHEL Base is **BYOL**. SSH users: RHEL/`ec2-user`, Ubuntu/`ubuntu`.

## Steps

1. **Pick the next queue item** from `docs/blog-roadmap.md` (or the topic the user named).
2. **Resolve facts**
   - Role repo + latest release tag
   - Marketplace product title for that OS/arch
   - Evidence path under `compliance/releases/<ver>/`
3. **Create** `blog/<slug>.html` using the hands-on template in the roadmap (subscribe → pin role → playbook → evidence). Copy structure/CSS from an existing hands-on post.
4. **Update** `blog/index.html` — add a Posts list entry (date + title + one-line blurb).
5. **Update** `sitemap.xml` with the new URL.
6. **Update** `docs/blog-roadmap.md` — remove the shipped item from the queue.
7. **Branch + PR** (unless user said not to). Title like `feat(blog): <topic>`. Merge only if the user asks.
8. **Smoke** — confirm no private monorepo URL; nav matches main site.

## Hands-on section order

1. Before you start  
2. Subscribe and launch Base  
3. Install the role (pinned tag)  
4. Run the playbook  
5. Check published evidence  
6. Related + contact  
