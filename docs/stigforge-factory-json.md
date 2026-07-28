# stigforge-factory.json

Published snapshot of the **StigForge** factory matrix for [stigready.com/#stigforge](https://stigready.com/#stigforge).

## Visibility (standing)

| Surface | Visibility |
|---|---|
| Exported Ansible **role repos** (`stigready/*-cis`, `*-stig`) | **public** |
| Factory monorepo `stigready/stigforge` | **always private** — never link it from stigready.com |

The marketing site links only to public role repos. Do not add a GitHub URL for the monorepo.

## Update from the factory monorepo

```bash
cd stigforge   # private clone
python3 scripts/publish-stigforge-factory-json.py ../stigready-web/stigforge-factory.json
```

Commit the web repo after a green **`pipeline`** on factory `main` (CI verify artifacts are the score source of truth).

## Fields

- **`cells`**: role + profile scores; the site renders the public role list and OpenSCAP scores only.
- **`factory_repo`**: metadata only (`stigready/stigforge`); not rendered as a public link.

Do not hand-edit matrix rows; regenerate from `matrix.yml` + verify artifacts.
