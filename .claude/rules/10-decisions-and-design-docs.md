<!-- GENERATED — DO NOT EDIT HERE.
     Authored in the claude-agents repo at config/rules/10-decisions-and-design-docs.md
     Vendored by scripts/sync-agent-config.sh. Edit it there and re-sync;
     an edit made in this repo is drift and fails the build. -->
# Decisions and design live in the register — always

**Owner, 2026-09-23:** *"we always use the decisions or design docs."* and
*"3214 should be a desision not this. we need to make sure we stay consisant."*

Design of record: [`design/governance.md`](https://github.com/stigready/claude-agents/blob/main/design/governance.md) ·
Register: [`design/decisions/`](https://github.com/stigready/claude-agents/blob/main/design/decisions/README.md)

## The test

> Does closing this require a **decision**, or a **change**?

| Needs a decision | Needs a change |
|---|---|
| A choice between options | A build failure |
| A standing requirement or invariant | A cell to triage |
| A question put to the owner | An owed fix |
| A design change — an invariant, a boundary, an interface between repos, a new mechanism | A version bump, a role update, an image build |
| **→ a numbered record in `design/decisions/`** | **→ a GitHub issue** |

A GitHub issue is the wrong instrument for a decision, and not because it gets ignored:

| | Register | Issue |
|---|---|---|
| Numbered in a sequence with no gaps | yes (`register-09`) | no |
| Must state Context / Decision / Consequences / Evidence | yes (`register-07`) | no |
| Indexed where the next reader looks | yes (`register-06`) | no |
| Carries `decided_by: owner` | yes | no |
| Survives being answered | superseded, never deleted | closed, and gone from view |

The failure mode is that the choice gets made in a comment thread, or never, and later
nothing explains why the program does what it does.

## Asking the owner

**Do not put a choice to the owner in chat or in an issue.** Write the record first, with
`status: proposed`, both options, the recommendation and its cost — then ask. The owner
approves or rejects the record. A rejected record stays: a decision not taken is history
too, and only the owner moves a record to `approved` or `rejected`.

`decisions-not-issues-01` fails a PR whose authored document defers a choice to an issue.
Citing an issue as **evidence** (*"found by #3214"*, *"fixed in #3225"*) is correct and is
not flagged.

## Every claim in a record is checked before it is written

A record's `## Evidence` section exists so a reader can re-run it. Run the command before
you write the row — not after, and not from memory.

This is not hypothetical care. On 2026-09-23 a draft of decision 0043 asserted that
`scripts/check-g149-build-history.py` *"has never existed"*. The register contradicted it
three records over. One `git log --all --diff-filter=A` showed it had been added in #2441
and deliberately deleted in #2529 — a different and more useful fact, which changed what
the record said. The same session produced two other wrong counts stated before checking:
*"cited three times"* (four) and *"the file has never existed"* about a second file (it had).

## Moving or deleting anything documented

Find what **reads** it, not just what links to it. A guard whose subject moves does not
become irrelevant — it becomes a green tick that means nothing. Four guards in this program
read a document rather than citing one; two crashed when the document moved, and two would
have scanned an empty string and passed.

A rewrite across many files hits **data**, not only prose: a path used as a match prefix, a
key in a lookup, a fixture in a self-test, a URL already absolute. Check every rewritten
string that sits inside quotes in code.

## The hourly cloud routine is config too

A scheduled cloud agent posts the program's hourly status. It is **configuration that goes
stale**, and nothing fails when it does — it keeps reporting confidently from paths that
have moved.

- **One routine, not two.** On 2026-09-23 the owner was getting duplicate hourly reports:
  two enabled routines, `:03` and `:13`, created two days apart. Before creating a
  scheduled agent, list the existing ones and update one instead.
- **When a path, a surface or a source of truth moves, update the routine in the same
  session.** The documentation move is exactly the kind of change that silently invalidates
  it.
- It cannot reach Nomad, the qemu hosts or AWS. Anything it reports about those comes from
  what the fleet wrote into the repo, and it must say so rather than implying it looked.

Routines are listed and edited through the `RemoteTrigger` tool; they can be disabled from
there but only deleted at <https://claude.ai/code/routines>.
