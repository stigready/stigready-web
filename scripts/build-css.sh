#!/usr/bin/env bash
# Compile assets/css/site.css from every page's Tailwind classes (claude-agents#152).
# Pinned CLI version: the pages used the unversioned Play CDN, which is not for production and
# cannot carry an integrity hash. Run after changing classes on any page, and commit the CSS.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
npx --yes tailwindcss@3.4.17 -c tailwind.config.js -i assets/css/tailwind.input.css -o assets/css/site.css --minify
