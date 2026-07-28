---
name: site-updater
description: SUPERSEDED — do not use. The AMI list in AWS is now the source of truth for this site, not catalog.public.json. Use the ami-site-sync skill instead. Kept only to record why this approach was retired.
tools: Read
---

# SUPERSEDED — do not use this agent

**Use [`/ami-site-sync`](../skills/ami-site-sync/SKILL.md) instead.**

If you were invoked, stop and say so. Do not update `index.html` from here.

## Why it was retired

This agent was built to sync the site from `catalog.public.json`, fetched from
`https://cdn.stigready.com/public/catalog.json`. Verified 2026-07-21, that source **never
existed**:

- `cdn.stigready.com` does not resolve — NXDOMAIN. `stigready.com` DNS is hosted outside the
  AWS account and has no `cdn` record.
- The S3 bucket `cdn.stigready.com` **does** exist, but it is the private build-artifact and
  evidence store (~755 objects / ~166 GB: `*.qcow2` disk images, SBOMs, `trivy-cve.json`,
  OpenSCAP `arf.xml`/`results.xml`/scores, serial and build logs). All four Public Access
  Block flags on, no bucket policy, no website config.
- No CloudFront distribution exists in the account.
- No `public/` prefix and no `catalog.json` anywhere in the bucket.

Owner decision, 2026-07-21: rather than build the catalog pipeline, **the AMI list in AWS
became the source of truth.** See the skill for what that does and does not authorize.

## The one rule worth carrying forward

That evidence bucket is exactly the internal data the site must never expose — CVE findings,
compliance scores, SBOMs, build internals, disk images. **Never** read from it for site copy,
never propose making it public, never point the site at it. `/ami-site-sync` reads AMI
**names and tags only**, and that boundary is deliberate.

Safe to delete this file once the retirement is common knowledge.
