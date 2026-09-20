#!/usr/bin/env python3
"""Validate the published site before it reaches stigready.com.

This repo had NO workflows and `required_status_checks: null` on `main`, so branch
protection enforced nothing. The program rule is that the green check IS the control; on
this repo there was no check to be green. Anything committed went live.

What is checked here is deliberately narrow — things that are objectively true or false
about the published artefacts, not style:

  1. every JSON and XML file parses (catalog.json drives the rendered catalog)
  2. catalog.json's shape: required keys, known availability values, sane scores
  3. AVAILABILITY DISCIPLINE — `availability: "available"` is the public "available" badge.
     Per .claude/rules/aws-marketplace.md it may only be set once a customer can actually
     subscribe, so it must carry a real Marketplace URL. A product claiming availability
     with no listing is a false public claim, which is the one failure mode on this repo
     that reaches customers rather than developers.
  4. no macOS "<name> 2.ext" duplicates (G191 — committed three times in one week)
  5. locally-referenced assets exist
  6. the vendored .claude/ config matches its recorded hashes — claude-agents' manifest
     says "a drift check fails the build if one is [hand-edited]", and with no workflow
     in this repo that check had nowhere to run

Exit 1 on any finding, with every finding printed — a validator that stops at the first
problem turns one fix round into five.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_KEYS = {"line", "os", "os_key", "arch", "profile", "availability", "marketplace_url"}
KNOWN_AVAILABILITY = {"available", "coming-soon"}

problems: list[str] = []


def tracked() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    return [ROOT / p for p in out.split("\0") if p]


def check_parsers(files: list[Path]) -> None:
    for f in files:
        if f.suffix == ".json":
            try:
                json.loads(f.read_text(encoding="utf-8"))
            except json.JSONDecodeError as e:
                problems.append(f"{f.relative_to(ROOT)}: invalid JSON — {e}")
        elif f.suffix in {".xml", ".svg"}:
            try:
                ET.parse(f)
            except ET.ParseError as e:
                problems.append(f"{f.relative_to(ROOT)}: invalid XML — {e}")


def check_catalog() -> None:
    path = ROOT / "catalog.json"
    if not path.is_file():
        problems.append("catalog.json is missing — the site renders from it")
        return
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return  # already reported by check_parsers

    products = doc.get("products")
    if not isinstance(products, list) or not products:
        problems.append("catalog.json: `products` must be a non-empty list")
        return

    for i, p in enumerate(products):
        where = f"catalog.json products[{i}]"
        name = f"{p.get('os_key')}:{p.get('profile')}"

        missing = REQUIRED_KEYS - set(p)
        if missing:
            problems.append(f"{where} ({name}): missing {sorted(missing)}")

        avail = p.get("availability")
        if avail not in KNOWN_AVAILABILITY:
            problems.append(
                f"{where} ({name}): availability {avail!r} not in {sorted(KNOWN_AVAILABILITY)}"
            )

        # The public claim. See the module docstring.
        if avail == "available":
            url = p.get("marketplace_url")
            if not url:
                problems.append(
                    f"{where} ({name}): availability is 'available' but marketplace_url is "
                    f"{url!r} — that publishes an 'available' badge for something nobody can "
                    "subscribe to"
                )
            elif not str(url).startswith("https://"):
                problems.append(f"{where} ({name}): marketplace_url is not https: {url!r}")

        score = p.get("score")
        if score is not None and not (isinstance(score, (int, float)) and 0 <= score <= 100):
            problems.append(f"{where} ({name}): score {score!r} is not a percentage")


def check_duplicates(files: list[Path]) -> None:
    dupes = [f for f in files if re.search(r" \d+\.[A-Za-z0-9]+$", f.name)]
    for f in dupes:
        problems.append(
            f"{f.relative_to(ROOT)}: macOS duplicate committed — a stale second copy of an "
            "authored file, and nothing says which is real (G191)"
        )


def check_local_assets(files: list[Path]) -> None:
    """Every reference that resolves to a file in this repo must exist.

    Three shapes are checked, because all three 404 the same way in a browser:
      - relative            assets/logo.png
      - root-relative       /applied/
      - own-origin absolute https://stigready.com/assets/logo.png

    Anything containing `${` is inside a JS template literal, resolved at runtime rather
    than statically — treating those as broken links is how this check becomes noise
    nobody reads. A path ending in `/` resolves to its index.html.
    """
    # href/src ONLY. `content=` on a <meta> is arbitrary text — descriptions, viewport,
    # robots — and treating it as a path produced 96 false positives on first run. The image
    # metas that DO carry a path are matched separately below, by property name.
    ref = re.compile(r'(?:href|src)="([^"]+)"')
    img_meta = re.compile(
        r'<meta[^>]+(?:property|name)="(?:og:image|twitter:image)"[^>]+content="([^"]+)"'
        r'|<meta[^>]+content="([^"]+)"[^>]+(?:property|name)="(?:og:image|twitter:image)"'
    )
    origin = "https://stigready.com"

    def resolve(html: Path, target: str) -> Path | None:
        t = target.split("?")[0].split("#")[0]
        if not t or "${" in t:
            return None
        if t.startswith(origin):
            t = t[len(origin):] or "/"
            base = ROOT
        elif t.startswith(("http://", "https://", "//", "mailto:", "data:", "tel:")):
            return None
        elif t.startswith("/"):
            base = ROOT
        else:
            base = html.parent
        t = t.lstrip("/")
        cand = base / t if t else base
        return cand / "index.html" if (target.endswith("/") or not Path(t).suffix) else cand

    for html in [f for f in files if f.suffix == ".html"]:
        body = html.read_text(encoding="utf-8", errors="ignore")
        targets = list(ref.findall(body))
        targets += [a or b for a, b in img_meta.findall(body)]
        seen: set[str] = set()
        for target in targets:
            cand = resolve(html, target)
            if cand is None or target in seen:
                continue
            seen.add(target)
            if not cand.exists():
                problems.append(
                    f"{html.relative_to(ROOT)}: missing local asset {target!r} "
                    f"(looked for {cand.relative_to(ROOT)})"
                )


def check_vendored_config() -> None:
    """The .claude/ tree is VENDORED from claude-agents and must not be hand-edited there.

    .sync-manifest.sha256 records the hash of every vendored file, so drift is detectable
    from this repo alone — no sibling clone, which matters because CI runners check out one
    repo. A file listed in the manifest that is missing or altered means someone edited the
    copy instead of the source, and the next sync will silently overwrite their work.
    """
    manifest = ROOT / ".claude" / ".sync-manifest.sha256"
    if not manifest.is_file():
        return  # repo may legitimately vendor nothing

    import hashlib

    for line in manifest.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            want, rel = line.split(None, 1)
        except ValueError:
            problems.append(f".claude/.sync-manifest.sha256: unparseable line {line!r}")
            continue
        target = ROOT / rel.strip()
        if not target.is_file():
            problems.append(f"{rel.strip()}: vendored file is missing — re-run sync-agent-config.sh")
            continue
        got = hashlib.sha256(target.read_bytes()).hexdigest()
        if got != want:
            problems.append(
                f"{rel.strip()}: vendored config edited in place. Author it in "
                "claude-agents/config/ and re-vendor; the next sync overwrites this copy."
            )


def main() -> int:
    files = tracked()
    check_parsers(files)
    check_catalog()
    check_duplicates(files)
    check_local_assets(files)
    check_vendored_config()

    if problems:
        print(f"validate-site: {len(problems)} problem(s)\n", file=sys.stderr)
        for p in problems:
            print(f"  ✗ {p}", file=sys.stderr)
        return 1

    print(f"validate-site: OK — {len(files)} tracked file(s) checked.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
