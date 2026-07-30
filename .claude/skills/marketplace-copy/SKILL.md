---
name: marketplace-copy
description: >-
  Draft or refresh AWS Marketplace listing copy for StigReady Base or Applied AMIs
  (title cues, short/long description, highlights) from catalog facts and published
  OpenSCAP scores. Use when preparing Marketplace text, seller listing updates, or
  aligning site copy with live listings.
---

# Marketplace copy (StigReady)

Produce Marketplace-ready text. Do **not** invent scores, OS/arch pairs, or availability.
AMIs and [catalog.json](../../../catalog.json) / AWS inventory are the source of truth for
what exists. Seller page: https://aws.amazon.com/marketplace/seller-profile?id=seller-h3qxnolnrqakk

## Inputs

1. Tier: **Base** or **Applied**
2. OS + arch (e.g. RHEL 9 x86_64, Ubuntu 24.04 arm64)
3. For Applied: profile (`cis-l1`, `cis-l2`, `stig`) and score from `catalog.json` or AMI `ScapScore` tag
4. Optional: current live listing title from Marketplace Catalog API (`prod-*`)

## Brand facts (keep accurate)

| Fact | Copy guidance |
|---|---|
| Base | STIG partition layout at install, SSH hardened, patched ISO build, Nitro boot-tested, x86_64 + arm64 |
| Applied | Remediated CIS L1/L2 or DISA STIG, scored in-build vs **raw unmodified SSG**, evidence bundle |
| RHEL | **BYOL** — customer supplies Red Hat subscription; StigReady does not sell RHEL licenses |
| StigForge | Public Ansible roles for bring-your-own remediation on Base; never link private monorepo |
| Pricing (site) | Base $0.02/hr or $149/yr; Applied $0.08/hr or $649/yr — software fee on top of EC2 |

## Output template

```markdown
## Listing — <OS> <arch> — <Base|Applied profile>

### Suggested product title
...

### Short description (≤1000 chars for MP short field — keep tighter if possible)
...

### Highlights (3–5 bullets)
- ...

### Long description (Markdown OK for internal review)
...

### Support / getting started URL
- Base: https://stigready.com/  (blog how-tos: https://stigready.com/blog/)
- Applied: https://stigready.com/applied/

### Do not claim
- Scores you cannot cite from catalog/AMI tags
- Affiliation with DISA/DoD/CIS/Red Hat/Canonical
- That Applied AL2023 exists if catalog/AWS has no Applied cells
```

## Guardrails

- No AMI IDs, account IDs, or private evidence bucket paths on public copy.
- No “coming soon” if the listing is live — say what’s included instead.
- Point Base+roles buyers at `/blog/` how-tos; Applied buyers at `/applied/` and score table.
