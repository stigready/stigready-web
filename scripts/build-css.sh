#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 StigReady
# SPDX-License-Identifier: LicenseRef-StigReady-Proprietary
# Compile assets/css/site.css from every page's Tailwind classes (claude-agents#152).
# Run after changing classes on any page or any inline script, and commit the CSS and its stamp.
#
# The Tailwind CLI is the upstream standalone binary for this version, checked against the sha256 below before it
# runs (stigready-web#67): one pinned file, no npm and so no unpinned transitive packages. The hashes are the release's
# sha256sums.txt. To move versions, change TAILWIND_VERSION and every hash together.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

TAILWIND_VERSION=3.4.17
# Upstream file name and its sha256 for each platform (a case, not an associative array: macOS ships bash 3.2).
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) plat=linux-x64 want=7d24f7fa191d2193b78cd5f5a42a6093e14409521908529f42d80b11fde1f1d4 ;;
  Linux-aarch64 | Linux-arm64) plat=linux-arm64 want=69b1378b8133192d7d2feb12a116fa12d035594f58db3eff215879e4ad8cf39b ;;
  Darwin-arm64) plat=macos-arm64 want=a1d0c7985759accca0bf12e51ac1dcbf0f6cf2fffb62e6e0f62d091c477a10a3 ;;
  Darwin-x86_64) plat=macos-x64 want=6cbdad74be776c087ffa5e9a057512c54898f9fe8828d3362212dfe32fc933a3 ;;
  *) echo "build-css: no pinned Tailwind CLI for $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

cache="${XDG_CACHE_HOME:-$HOME/.cache}/stigready-web"
cli="$cache/tailwindcss-$TAILWIND_VERSION-$plat"
if [ ! -x "$cli" ] || [ "$(sha256 "$cli")" != "$want" ]; then
  mkdir -p "$cache"
  tmp=$(mktemp "$cache/tailwindcss.XXXXXX")
  curl -fsSL -o "$tmp" \
    "https://github.com/tailwindlabs/tailwindcss/releases/download/v$TAILWIND_VERSION/tailwindcss-$plat"
  got=$(sha256 "$tmp")
  if [ "$got" != "$want" ]; then
    rm -f "$tmp"
    echo "build-css: tailwindcss-$plat sha256 $got, want $want; not running it" >&2
    exit 1
  fi
  chmod +x "$tmp"
  mv "$tmp" "$cli"
fi

"$cli" -c tailwind.config.js -i assets/css/tailwind.input.css -o assets/css/site.css --minify
# Record what this CSS was built from; the CINC control web-site-css-fresh fails when the pages, config or CSS no longer match it.
python3 scripts/css_stamp.py --write
