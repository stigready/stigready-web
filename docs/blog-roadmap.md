# Blog roadmap (maintainer only)

Internal queue for upcoming Base + StigForge how-tos. **Do not render this on stigready.com** — the public blog shows only published posts (`blog/index.html`).

When a post ships: add it to the public Posts list, add the URL to `sitemap.xml`, remove it from the queue below.

## Standing rules

- Link **public** role repos (`stigready/*-cis`, `*-stig`) and Marketplace seller page only.
- Never link the private factory monorepo `stigready/stigforge`.
- Pin Ansible installs to a **git tag**, never `main`.
- Marketplace CTA: [seller profile](https://aws.amazon.com/marketplace/seller-profile?id=seller-h3qxnolnrqakk).

## Queue (next up first)

1. RHEL 9 Base + `rhel9_cis` (Level 1 / Level 2)
2. Ubuntu 24.04 Base + `ubuntu24_stig`
3. Rocky 9 / Alma 9 Base with RHEL 9 StigForge roles
4. arm64 (Graviton): Base + roles on the same matrix cell
5. RHEL 8 and RHEL 10 Base + matching StigForge roles
6. Re-score after remediation: OpenSCAP evidence and `make prove`
7. Base vs Applied: buy remediated AMIs or bring your own roles
8. Pinning role tags in Packer / golden-image pipelines
9. Amazon Linux 2023 Base today; Applied CIS/STIG when built

## Hands-on post template

1. Subscribe + launch Base (seller page + product title + SSH user)
2. `requirements.yml` with pinned tag
3. Minimal `site.yml` + `ansible-playbook`
4. Link role `compliance/releases/<ver>/` + `#stigforge` scores
5. Related posts + contact
