# stigforge-factory.json

Published snapshot of the **StigForge** factory matrix for [stigready.com/#stigforge](https://stigready.com/#stigforge).

## Update from the factory monorepo

```bash
cd stigforge
python3 scripts/publish-stigforge-factory-json.py ../stigready-web/stigforge-factory.json
```

Commit both repos after a green **`pipeline`** on `main` (CI verify artifacts are the score source of truth).

## Fields

- **`image_cutover`**: `in_progress` until the private image factory pins StigForge roles (Phase D).
- **`factory_cutover_ready`**: factory precondition (all required matrix cells green) — not an AMI cutover signal.
- **`pilot_review`**: exemplar private role-repo export (when configured in `release/registry.yml`).

Do not hand-edit matrix rows; regenerate from `matrix.yml` + verify artifacts.
