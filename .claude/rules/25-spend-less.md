<!-- GENERATED — DO NOT EDIT HERE.
     Authored in the claude-agents repo at config/rules/25-spend-less.md
     Vendored by scripts/sync-agent-config.sh. Edit it there and re-sync;
     an edit made in this repo is drift and fails the build. -->
# Spend less — the owned fleet before the meter

**Owner, 2026-09-24:** *"we need to alwau look to spend less"* — said when offered
"raise the Actions budget" as one of two fixes for a CI outage.

Record: [0050](https://github.com/stigready/claude-agents/blob/main/design/decisions/0050-pr-checks-run-on-the-fleet-we-own.md)

## The rule

- **Offer the cheaper option first.** "Spend more" is never the default fix. Reach for the
  fleet we already own (qemu-1..4), a local QEMU run, or a lower cadence before a budget
  increase.
- **Price every recommendation.** A proposal that costs money and does not say how much,
  and what the cheaper alternative would be, is incomplete.
- **Cheapest is not moving the work — it is not doing it.** Move waste onto our own
  hardware only after asking whether the work needs to happen at all.

## Never at the cost of a gate

Spending less does **not** license weakening a gate, a floor, a baseline or branch
protection. 0050 changes *where* checks run, never *whether* they run. A merge freeze is
preferable to an unreviewed merge — see
[`20-security-invariants.md`](20-security-invariants.md).

## A metered dependency in a critical path is a design risk

On 2026-09-24 the org hit 100% of its Actions budget. Because `main` requires `validate`
(strict, `enforce_admins`), **every merge in the program stopped** — including the fixes for
that outage. Cost and resilience pointed the same way: the meter was a single point of
failure, not just a bill.

## What it looked like in practice

September, measured with `gh api ".../settings/billing/usage?year=2026&month=9"`:

| Repo | Minutes | Net |
|---|---|---|
| stigready | 6,138 | **$19.32** |
| claude-agents | 172 | $0.52 |
| stigvalidated | 32 | $0.16 |
| stigforge | 9 | $0.00 |

**stigforge is the precedent, not the problem** — it moved to self-hosted on 2026-07-28 and
bills 9 minutes a month.

93% of stigready's runs were the factory's own housekeeping branches; only 14 of 200 were
real changes. The largest consumer carried **no information**: the Batman fill restamped
`filled_at` every 5 minutes, so 35 case files "changed", were force-pushed, and triggered a
full `pr-checks` run whose entire diff was 35 timestamp lines.

**Before adding a step that commits, pushes or opens a PR on a schedule, ask what triggers
downstream and whether the content actually changed.** A no-op write is not free — it costs
a CI run every time.

## Query it properly

Pass `year` and `month`. Without them the endpoint returns a first page that can attribute
the spend to the wrong repo — it did, and the first version of 0050 blamed stigforge.
