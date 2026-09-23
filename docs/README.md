# Documentation moved to claude-agents

Owner direction, 2026-09-23: *"i want all docs reviewd and moved to claude-agents repo.
we need all docs in 1 place."*

The four documents that were here are now in
[`claude-agents/docs/stigready-web/`](https://github.com/stigready/claude-agents/tree/main/docs/stigready-web):
`blog-roadmap.md`, `program-workspace.md`, `site-merge.md`, `stigforge-factory-json.md`.

They were **moved, not copied** — no code here reads a document, so a single copy is safe,
and a second copy is the duplication the move exists to remove. Edit them in claude-agents.

**Do not add a document here.** `validate-site.py` fails the build on one.
