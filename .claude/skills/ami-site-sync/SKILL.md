---
name: ami-site-sync
description: Sync the Base Catalog table in index.html against the base AMIs actually built in AWS (OS, arch, availability), then stage the diff on a branch and open a draft PR. The AMI list is the source of truth for this site. Use after a build run lands — especially during the aarch64 rollout — or when asked whether the site matches what's built.
---

# AMI → site sync

Regenerate the **Base Catalog** rows of [index.html](../../../index.html) from the base AMIs
that actually exist in AWS, so the site never claims an OS or architecture that isn't built.

## The AMI list is the source of truth

Owner decision, 2026-07-21: **the AMIs in AWS are the source of truth for this site.** Not
`catalog.public.json` — that endpoint was never built (`cdn.stigready.com` is NXDOMAIN, and
the bucket behind that name is the private evidence store). The
[site-updater](../../agents/site-updater.md) agent is **superseded** by this skill. One source
of truth only; two is how the site drifts.

### What the AMI list can and cannot decide

It is authoritative for **existence**: which OSes exist, which arches are built, and at what
version. If the site claims an OS or arch that `inventory.sh` doesn't return, the site is
wrong — fix the site.

It is **silent** on commercial state. An AMI cannot tell you whether a product is sold,
priced, listed on Marketplace, or under support. Those stay owner decisions, carried forward
from the existing row (see *Built ≠ released*). "The AMI list is the source of truth" means
**an AMI is required** for a row to exist — never that its existence alone justifies a claim.

So: an OS disappearing from AWS means remove the row. An OS appearing means add the row as
`Coming soon` and ask. Neither case is a judgement call; the availability wording is.

## Hard limits — do not widen these

Read **only** AMI `Name` and the `OS` / `Arch` / `Lifecycle` / `Product` tags, via
`scripts/inventory.sh`. Specifically:

- **Never** put an AMI ID, snapshot ID, or region on the site.
- **Never** read the `cdn.stigready.com` bucket. It holds `trivy-cve.json`, OpenSCAP results
  and scores, SBOMs, and disk images — all forbidden on the public site, all irrelevant here.
- **Never** publish a compliance score, CVE count, or benchmark claim. This is the base tier;
  those belong to stigapplied and only via the catalog.
- **Never** invent availability. An AMI existing means *built*, not *released* — see below.
- Show only `line == stigready` base images (`stigready-base-*`). Ignore `stigapplied-*`;
  that's the other site.

## Built ≠ released

`scripts/inventory.sh` tells you what is **built**. It cannot tell you what is **sold**.
Availability wording is a human decision and is carried over from the existing row:

| Wording | Meaning | Set by |
|---|---|---|
| `Early access` | built, not yet on Marketplace | current default for community-licensed OSes |
| `BYOL — on request` | genuine Red Hat, no entitlement attached | **every** `rhel*` row, all versions |
| `Coming soon` | **not** built, or built but deliberately unannounced | human only |

Standing decisions (owner, 2026-07-21): **every genuine RHEL row is BYOL**, at every version —
never `Coming soon` once built. The RHEL family carries **8, 9, and 10 for all variants**
(Rocky, AlmaLinux, RHEL); a missing version there is a build gap to report, not a product gap.
Rocky and AlmaLinux are community redistributions — they are *not* BYOL.

Never promote a row to a more available state on your own. If an AMI appears for an OS with no
row, add the row as `Coming soon` and flag it in the PR for a human to decide — do not
pre-announce. Removing or downgrading a row when its AMI disappears is fine and expected.

## Steps

1. **Inventory** — `./.claude/skills/ami-site-sync/scripts/inventory.sh` (optional args:
   profile, region; defaults `stigready` / `us-east-1`). Output is `os|arch|version`, one
   line per OS/arch, highest version kept.
2. **Map** each OS slug to display name and family:

   | slug | Base image | Family |
   |---|---|---|
   | `ubuntu2404` | Ubuntu 24.04 LTS | Debian |
   | `ubuntu2604` | Ubuntu 26.04 LTS | Debian |
   | `amazon2023` | Amazon Linux 2023 | Amazon |
   | `rocky8` / `rocky9` / `rocky10` | Rocky Linux 8/9/10 | RHEL |
   | `alma8` / `alma9` / `alma10` | AlmaLinux 8/9/10 | RHEL |
   | `rhel8` / `rhel9` / `rhel10` | Red Hat Enterprise Linux 8/9/10 | RHEL |

   Unknown slug → stop and ask. Never guess a display name.
3. **Regenerate only `<tbody>`** of the `#catalog` table. Keep row order: Ubuntu, Amazon,
   Rocky, AlmaLinux, RHEL — ascending version within each family. Arch cell lists the arches
   actually built, `x86_64 · arm64`. Touch nothing else — layout, copy, branding, and the
   legal/trademark footer are hand-authored and legally reviewed.
4. **Sweep the arch claims elsewhere.** The AWS-Native blurb and the meta
   description/keywords also name architectures and OSes; a row change that leaves those
   stale is a half-done sync. Report any you change.
5. **Branch + draft PR.** Never push to `main`. PR body must list: OS/arch pairs added,
   removed, or changed; every row still `Coming soon` and why; and any OS built in AWS but
   intentionally unlisted. A human merges.

## If a catalog endpoint ever ships

It does not supersede this skill by default. `catalog.public.json` was the *old* plan; the
owner has since made the AMI list authoritative. If a catalog appears later, raise it as a
decision — do not silently switch sources.

## Merge gate during the aarch64 rollout

While arm64 is rolling out, the PR stays a **draft** until every listed OS has both arches
built, or the missing ones are explicitly accepted as x86_64-only. Re-run this skill to
refresh the branch as builds land — that's the intended workflow, not a rebuild from scratch.
