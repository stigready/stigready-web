#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 StigReady
# SPDX-License-Identifier: LicenseRef-StigReady-Proprietary
"""Copyright-header guard (owner, 2026-10-26: "we need to get everything copyrighted").

Check mode (default) fails when:
  * a tracked source file lacks the SPDX header
        SPDX-FileCopyrightText: <year> StigReady
        SPDX-License-Identifier: <an id allowed in .spdx-headers>
    in its first 15 lines, unless .spdx-headers excludes it (generated or third-party files);
  * any tracked text file names an organisation that must never appear in this org's files
    (the pattern is built from parts so this file does not match itself).

--fix inserts the header into every source file that lacks one, after a shebang, a Python
coding line, Dockerfile parser directives or an HTML doctype. Files that already carry
another party's copyright or SPDX header are reported and left alone: add them to the
exclusions in .spdx-headers so their upstream notice is kept.

Config: .spdx-headers at the repository root, one directive per line:
    license <SPDX expression>      the first is what --fix writes; any listed one passes
    license-for <glob> <SPDX>      files matching the glob carry exactly this licence (a part of
                                   the repo that already declares its own, e.g. a CINC profile)
    exclude <glob>                 fnmatch glob on the repo-relative path (** matches /)
Standard library only; the file list comes from `git ls-files`.
"""
from __future__ import annotations

import argparse
import fnmatch
import re
import subprocess
import sys
from pathlib import Path

HOLDER = "StigReady"
YEAR = "2026"
HEAD_LINES = 15

HASH = {".py", ".sh", ".bash", ".rb", ".yml", ".yaml", ".tf", ".hcl", ".ps1", ".toml", ".mk"}
SLASH = {".go", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}
BLOCK = {".css"}
ANGLE = {".html", ".htm"}
HASH_NAMES = re.compile(r"^(Makefile|Dockerfile(\..+)?|.+\.Dockerfile)$")

COPYRIGHT_RE = re.compile(r"SPDX-FileCopyrightText:\s*(?:19|20)\d\d(?:-(?:19|20)\d\d)?\s+" + HOLDER + r"\b")
LICENSE_RE = re.compile(r"SPDX-License-Identifier:\s*(.+?)\s*(?:-->|\*/|#\}|$)", re.M)
OTHER_HOLDER_RE = re.compile(r"(?i)(copyright\s*(\(c\)|©)?\s*(?:19|20)\d\d|SPDX-FileCopyrightText|@license)")
GENERATED_RE = re.compile(r"(?i)(DO NOT EDIT|@generated|^\s*//\s*Code generated)")
# Built from parts: a literal would make this file fail its own check.
FORBIDDEN_RE = re.compile("(?i)" + "|".join(["l" + "[y]" + "nk", "e" + "[l]" + "veo"]))


def style_for(path: str) -> str | None:
    name = path.rsplit("/", 1)[-1]
    if HASH_NAMES.match(name):
        return "hash"
    ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
    if ext in HASH:
        return "hash"
    if ext in SLASH:
        return "slash"
    if ext in BLOCK:
        return "block"
    if ext in ANGLE:
        return "angle"
    return None


def header_lines(style: str, license_id: str) -> list[str]:
    a = f"SPDX-FileCopyrightText: {YEAR} {HOLDER}"
    b = f"SPDX-License-Identifier: {license_id}"
    if style == "hash":
        return [f"# {a}", f"# {b}"]
    if style == "slash":
        return [f"// {a}", f"// {b}"]
    if style == "block":
        return [f"/* {a} */", f"/* {b} */"]
    return [f"<!-- {a} -->", f"<!-- {b} -->"]


def load_config(root: Path) -> tuple[list[str], list[str], list[tuple[str, str]]]:
    cfg = root / ".spdx-headers"
    if not cfg.is_file():
        sys.exit(f"check-spdx-headers: {cfg} is missing")
    licenses: list[str] = []
    excludes: list[str] = []
    overrides: list[tuple[str, str]] = []
    for raw in cfg.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition(" ")
        if key == "license":
            licenses.append(value.strip())
        elif key == "exclude":
            excludes.append(value.strip())
        elif key == "license-for":
            glob, _, expr = value.strip().partition(" ")
            overrides.append((glob, expr.strip()))
        else:
            sys.exit(f"check-spdx-headers: unknown directive {key!r} in .spdx-headers")
    if not licenses:
        sys.exit("check-spdx-headers: .spdx-headers names no licence")
    return licenses, excludes, overrides


def excluded(path: str, globs: list[str]) -> bool:
    for g in globs:
        if fnmatch.fnmatchcase(path, g):
            return True
        if g.endswith("/**") and path.startswith(g[:-2]):
            return True
        if g.startswith("**/") and fnmatch.fnmatchcase(path, g[3:]):
            return True
    return False


def tracked(root: Path) -> list[str]:
    out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True).stdout
    return [p for p in out.decode().split("\0") if p and (root / p).is_file() and not (root / p).is_symlink()]


def read_text(p: Path) -> str | None:
    data = p.read_bytes()
    if b"\0" in data[:8192]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def insert_at(lines: list[str], style: str, path: str) -> int:
    i = 0
    if lines and lines[0].startswith("#!"):
        i = 1
    if style == "hash" and path.endswith(".py") and len(lines) > i and re.match(r"^#.*coding[:=]", lines[i]):
        i += 1
    if style == "hash" and HASH_NAMES.match(path.rsplit("/", 1)[-1]) and "Dockerfile" in path:
        while i < len(lines) and re.match(r"^#\s*(syntax|escape|check)\s*=", lines[i], re.I):
            i += 1
    if style == "angle" and lines and re.match(r"(?i)^\s*<!doctype", lines[0]):
        i = 1
    return i


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--fix", action="store_true", help="insert missing headers")
    ap.add_argument("--root", default=".", help="repository root (default: .)")
    args = ap.parse_args()
    root = Path(args.root).resolve()
    licenses, excludes, overrides = load_config(root)

    missing: list[str] = []
    wrong_license: list[str] = []
    third_party: list[str] = []
    forbidden: list[str] = []
    fixed = 0
    for path in tracked(root):
        full = root / path
        text = read_text(full)
        if text is None:
            continue
        if FORBIDDEN_RE.search(path) or FORBIDDEN_RE.search(text):
            forbidden.append(path)
        style = style_for(path)
        if style is None or excluded(path, excludes):
            continue
        head = "\n".join(text.splitlines()[:HEAD_LINES])
        own = next((expr for glob, expr in overrides if excluded(path, [glob])), None)
        allowed = [own] if own else licenses
        if COPYRIGHT_RE.search(head):
            m = LICENSE_RE.search(head)
            if not m or m.group(1) not in allowed:
                wrong_license.append(f"{path}: {m.group(1) if m else 'no SPDX-License-Identifier'}")
            continue
        if GENERATED_RE.search(head):
            third_party.append(f"{path}: generated (add an exclude)")
            continue
        if OTHER_HOLDER_RE.search(head):
            third_party.append(f"{path}: carries another notice (add an exclude to keep it)")
            continue
        if not args.fix:
            missing.append(path)
            continue
        lines = text.split("\n")
        at = insert_at(lines, style, path)
        add = header_lines(style, allowed[0])
        if style == "slash" and path.endswith(".go"):
            add = add + [""]
        lines[at:at] = add
        full.write_text("\n".join(lines), encoding="utf-8")
        fixed += 1

    for p in third_party:
        print(f"check-spdx-headers: third-party or generated, not changed: {p}", file=sys.stderr)
    if args.fix:
        print(f"check-spdx-headers: added the header to {fixed} file(s)")
    rc = 0
    if missing:
        rc = 1
        print(f"check-spdx-headers: {len(missing)} source file(s) lack 'SPDX-FileCopyrightText: {YEAR} {HOLDER}'"
              f" and 'SPDX-License-Identifier: {licenses[0]}' (run scripts/check-spdx-headers.py --fix,"
              " or exclude a generated or third-party file in .spdx-headers):")
        for p in missing:
            print(f"  {p}")
    if wrong_license:
        rc = 1
        print(f"check-spdx-headers: licence not the one .spdx-headers sets for the path (default {licenses}):")
        for p in wrong_license:
            print(f"  {p}")
    if third_party and not args.fix:
        rc = 1
        print("check-spdx-headers: source files with no StigReady header that are not excluded:")
        for p in third_party:
            print(f"  {p}")
    if forbidden:
        rc = 1
        print("check-spdx-headers: a forbidden organisation name appears in:")
        for p in forbidden:
            print(f"  {p}")
    if rc == 0 and not args.fix:
        print("check-spdx-headers: ok")
    return rc


if __name__ == "__main__":
    sys.exit(main())
