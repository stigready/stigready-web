<!-- GENERATED — DO NOT EDIT HERE.
     Authored in the claude-agents repo at config/rules/15-read-the-design-first.md
     Vendored by scripts/sync-agent-config.sh. Edit it there and re-sync;
     an edit made in this repo is drift and fails the build. -->
# Read the design before diagnosing. Never infer from symptoms.

**Owner, 2026-09-24:** *"we should always refer to the design documented of each process. we
are to never make assumptions."*

Record: [0047](https://github.com/stigready/claude-agents/blob/main/design/decisions/0047-read-the-design-before-diagnosing.md) ·
Sibling rule for compliance requirements: [`30-stig-is-the-source.md`](30-stig-is-the-source.md)

## Before you say why something is broken

1. **Name what you read.** Which design record, how-to, or module. *"It looks like X"* is not
   a diagnosis — say "hypothesis" when it is one.
2. **Test the thing you are about to blame, first.** Claim "the token is bad" → use the
   token. Claim "the surface is stale" → check whether it can read its source at all. One
   command beats an afternoon.
3. **Check your own capability before declaring a blocker.** Do not report something as
   blocked on the owner until you have tried it.
4. **Say "I do not know yet."** It is a complete status. A confident wrong answer sends the
   work in the wrong direction.

## What this cost, once

2026-09-23/24: the factory sat idle **thirteen hours** with seven buildable base cells. The
cause was one function ignoring a subprocess exit code. The day before finding it produced
three confident diagnoses, all wrong:

| Asserted | Actually |
|---|---|
| The Nomad token expired | Valid — no expiry, HTTP 200 on every endpoint. Never tested. |
| No credentials to fix it; owner must | Vault `root` + a Nomad management token were in the session |
| The heartbeat 403 blocked dispatch | Real bug, unrelated — a reporting probe, not the dispatch path |

The same day, a fake AMI row was removed from `main` **five times** and blamed on stale
branches, on merge resolution, and on the author — before anyone read
`promote_requires_score.rb` and found the control was *writing* it.

## The defect class this exists for

A component that cannot distinguish **"I could not find out"** from **"there is nothing"**.
Three instances in one day:

| Component | Reported |
|---|---|
| `govcloud_missing_base_keys()` | a failed AWS call as "no gaps" → `action: wait` |
| `factory-heartbeat.py` | a 403 as "BUILDING — 4 legs in flight" |
| `merge-routine-program-prs.sh` | a dead merge loop as success (`\|\| true` ×10) |

You cannot reason your way to these: the behaviour is **designed to look normal**. Only the
source says what should happen.

**Finding one is not enough — fix it as a class.** Each of the three above now has a control
(`planner-gaps-fail-loud-01`, `merge-loop-visible-01`, the heartbeat's authenticated probe),
and when a scan or guard is involved, check the whole family rather than the one instance:
thirteen control files shared one unsafe `File.read`.
