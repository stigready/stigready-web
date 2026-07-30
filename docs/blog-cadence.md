# Blog cadence (StigReady)

Weekly editorial calendar for [stigready.com/blog/](https://stigready.com/blog/).
Publish day: **Thursday** (aligns with this launch week). One post per week after the launch set.

## Standing rules

- Link **public** role repos (`stigready/*-cis`, `*-stig`) and Marketplace seller page only.
- Never link the private factory monorepo `stigready/stigforge`.
- Pin Ansible installs to a **git tag** (e.g. `v0.2.4-private-review`), never `main`.
- Marketplace CTA: [seller profile](https://aws.amazon.com/marketplace/seller-profile?id=seller-h3qxnolnrqakk).
- When a post ships, add it under **Published** on `blog/index.html`, mark the cadence row Published, and add the URL to `sitemap.xml`.

## Launch set (week of 2026-07-30) — published

| Slug | Title |
|---|---|
| `base-plus-stigforge-roles.html` | StigReady Base + StigForge roles (overview) |
| `rhel9-base-stigforge-stig.html` | RHEL 9 Base + `rhel9_stig` |
| `ubuntu24-base-stigforge-cis.html` | Ubuntu 24.04 Base + `ubuntu24_cis` |

## Scheduled

| Week of | Topic | Role / focus |
|---|---|---|
| 2026-08-06 | RHEL 9 Base + CIS | `rhel9_cis` L1/L2 |
| 2026-08-13 | Ubuntu 24.04 Base + STIG | `ubuntu24_stig` |
| 2026-08-20 | Rocky 9 / Alma 9 Base with RHEL 9 roles | community rebuilds + BYOL contrast |
| 2026-08-27 | arm64 (Graviton) | same matrix cell, arm64 Base listing |
| 2026-09-03 | RHEL 8 and RHEL 10 | `rhel8_*` / `rhel10_*` |
| 2026-09-10 | Re-score after remediation | OpenSCAP + `make prove` |
| 2026-09-17 | Base vs Applied | buy remediated AMIs vs BYO roles |
| 2026-09-24 | Packer / golden-image pins | role tags in bake pipelines |
| 2026-10-01 | Amazon Linux 2023 | Base today; Applied when built |

## Template for each hands-on post

1. Subscribe + launch Base (seller page + product title + SSH user)
2. `requirements.yml` with pinned tag
3. Minimal `site.yml` + `ansible-playbook`
4. Link role `compliance/releases/<ver>/` + `#stigforge` scores
5. Related posts + contact
