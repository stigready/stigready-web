#!/usr/bin/env bash
# Node and the renderer's packages for check-copy-vs-marketplace.py (decision 0114), pinned.
#
#   scripts/render/setup.sh <render-dir> <node-dir>    prints the node binary's path on stdout
#
# Node: NODE_VERSION exactly. In order: the runner image's /opt/node (cairn Dockerfile.runner), a tarball in the
# dependency mirror ($MIRROR_DIR, /opt/mirror, /mnt/stigready/mirror: node/<tarball>), then nodejs.org. Every tarball is
# checked against NODE_SHA256 before it is unpacked. Packages: `npm ci` from <render-dir>/package-lock.json (each
# tarball checked against its sha512 integrity), from a mirror npm cache (npm/) offline first, then the registry.
# Install scripts never run. Anything that cannot be had exits non-zero: the checker then cannot render, and fails.
set -euo pipefail
NODE_VERSION=v24.21.0
NODE_TARBALL="node-${NODE_VERSION}-linux-x64.tar.xz"
NODE_SHA256=fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6   # nodejs.org SHASUMS256.txt

render_dir=${1:?usage: setup.sh <render-dir> <node-dir>}
node_dir=${2:?usage: setup.sh <render-dir> <node-dir>}

node=
for cand in /opt/node/bin/node "${node_dir}/bin/node"; do
  if [ -x "$cand" ] && [ "$("$cand" --version)" = "$NODE_VERSION" ]; then node=$cand; break; fi
done
if [ -z "$node" ]; then
  tmp=$(mktemp -d)
  got=
  for d in "${MIRROR_DIR:-}" /opt/mirror /mnt/stigready/mirror; do
    if [ -n "$d" ] && [ -f "$d/node/$NODE_TARBALL" ]; then cp "$d/node/$NODE_TARBALL" "$tmp/"; got="$d/node"; break; fi
  done
  if [ -z "$got" ]; then
    curl -fsSLo "$tmp/$NODE_TARBALL" "https://nodejs.org/dist/${NODE_VERSION}/${NODE_TARBALL}"
    got=nodejs.org
  fi
  echo "${NODE_SHA256}  $tmp/$NODE_TARBALL" | sha256sum -c - >&2
  mkdir -p "$node_dir"
  tar -xJf "$tmp/$NODE_TARBALL" -C "$node_dir" --strip-components=1
  rm -rf "$tmp"
  node="${node_dir}/bin/node"
  echo "render setup: node ${NODE_VERSION} from ${got}" >&2
fi
npm="$(dirname "$node")/npm"
export PATH="$(dirname "$node"):$PATH"
# The runner's HOME is not writable: npm gets its own cache and no update check. HTTPS_PROXY (a PR runner's only way
# out) is honoured by npm as it is by pip.
npm_config_cache="$(mktemp -d)"
export npm_config_cache npm_config_update_notifier=false

done_ci=
for d in "${MIRROR_DIR:-}" /opt/mirror /mnt/stigready/mirror; do
  [ -n "$d" ] && [ -d "$d/npm" ] || continue
  cache=$(mktemp -d)
  cp -R "$d/npm/." "$cache/"
  if (cd "$render_dir" && "$npm" ci --ignore-scripts --no-audit --no-fund --offline --cache "$cache") >&2; then
    done_ci="$d/npm"; rm -rf "$cache"; break
  fi
  rm -rf "$cache"
  echo "render setup: $d/npm does not hold the whole lock; trying the next source" >&2
done
if [ -z "$done_ci" ]; then
  (cd "$render_dir" && "$npm" ci --ignore-scripts --no-audit --no-fund) >&2
  done_ci=registry
fi
echo "render setup: packages from ${done_ci} ($(cd "$render_dir" && "$node" -p '"jsdom " + JSON.parse(require("fs").readFileSync("node_modules/jsdom/package.json")).version'))" >&2
echo "$node"
