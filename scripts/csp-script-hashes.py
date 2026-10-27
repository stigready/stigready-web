#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 StigReady
# SPDX-License-Identifier: LicenseRef-StigReady-Proprietary
"""Write each page's inline-script hashes into its Content-Security-Policy (stigready-web#67).

The CSP's script-src has no 'unsafe-inline': a browser runs an inline <script> only when its sha256 is listed. After
editing an inline script, run this and commit the pages:

  scripts/csp-script-hashes.py --write

It rewrites the 'sha256-...' sources in every tracked page's script-src to exactly the hashes of that page's inline
executable scripts (no src, and not a JSON type), keeping the other sources in order. The assertion is the CINC
control web-csp-inline-scripts-hashed (decision 0003); this script only writes.
"""
from __future__ import annotations

import base64
import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = re.compile(r"<script\b((?:[^>\"']|\"[^\"]*\"|'[^']*')*)>(.*?)</script\s*>", re.S | re.I)
CSP_META = re.compile(r'(<meta\s+http-equiv="Content-Security-Policy"\s+content=")([^"]*)(")', re.I)
HASH_SOURCE = re.compile(r"'sha256-[A-Za-z0-9+/]+=*'")


def inline_hashes(body: str) -> list[str]:
    out: list[str] = []
    for attrs, text in SCRIPT.findall(body):
        a = attrs.lower()
        if re.search(r"\bsrc\s*=", a) or re.search(r"\btype\s*=\s*[\"']?application/(?:ld\+)?json", a):
            continue
        digest = base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode()
        source = f"'sha256-{digest}'"
        if source not in out:
            out.append(source)
    return out


def rewrite(policy: str, hashes: list[str]) -> str:
    parts = []
    for part in policy.split(";"):
        words = part.split()
        if words and words[0].lower() == "script-src":
            kept = [w for w in words[1:] if not HASH_SOURCE.fullmatch(w)]
            # 'self' first, then the hashes, then the rest (hosts).
            head = [w for w in kept if w == "'self'"]
            tail = [w for w in kept if w != "'self'"]
            part = " " + " ".join(["script-src", *head, *hashes, *tail])
        parts.append(part)
    return ";".join(parts)


def main(argv: list[str]) -> int:
    if argv != ["--write"]:
        print(__doc__, file=sys.stderr)
        return 2
    pages = subprocess.run(["git", "ls-files", "-z", "--", "*.html"], cwd=ROOT, capture_output=True, text=True,
                           check=True).stdout.split("\0")
    for rel in filter(None, pages):
        path = ROOT / rel
        body = path.read_text(encoding="utf-8")
        hashes = inline_hashes(body)
        new = CSP_META.sub(lambda m: m.group(1) + rewrite(m.group(2), hashes).lstrip() + m.group(3), body)
        if new != body:
            path.write_text(new, encoding="utf-8")
            print(f"{rel}: script-src hashes {len(hashes)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
