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
     It may only be set once a customer can actually
     subscribe, so it must carry a real Marketplace URL. A product claiming availability
     with no listing is a false public claim, which is the one failure mode on this repo
     that reaches customers rather than developers.
  4. no macOS "<name> 2.ext" duplicates
  5. locally-referenced assets exist
  6. NOTHING PRIVATE IS PUBLISHED — this repo is public and served as-is, so agent/editor
     config (.claude/, .cursor/, CLAUDE.md, AGENTS.md) must not be tracked, and no tracked
     file may reference a private org repository
  7. no docs/ tree (documentation is maintained elsewhere)
  8. no Play CDN or unpinned third-party script, and a CSP meta tag on every page
  9. assets/css/site.css is what scripts/build-css.sh wrote for the current pages, config and
     Tailwind version (scripts/css_stamp.py; the runners cannot run Tailwind, so the build stamps it)

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
            "authored file, and nothing says which is real"
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


PRIVATE_REPOS = (
    "stigforge", "claude-agents", "stigready", "stigvalidated", "cairn", "build-reports",
    "cmmc-agents-field-manual",
)
# stigready/<private> not followed by another name character, so public repos such as
# stigready/stigready-web or stigready/rhel9-stig never match.
PRIVATE_REF = re.compile(
    r"stigready/(?:" + "|".join(re.escape(r) for r in PRIVATE_REPOS) + r")(?:-\w+)?(?![\w-])"
    r"|stigready/stigvalidated-\w+"
)
AGENT_CONFIG = (".claude/", ".cursor/")
AGENT_FILES = {"CLAUDE.md", "AGENTS.md"}
TEXT_SUFFIXES = {".html", ".json", ".xml", ".txt", ".md", ".js", ".css", ".py", ".sh", ".yml", ".yaml", ""}


def check_nothing_private(files: list[Path]) -> None:
    """This repo is public and GitHub Pages serves every tracked file.

    Agent and editor config once rode along here and was reachable on the live site. It
    describes internal infrastructure and has no place in a public repo, so it must not be
    tracked at all. Likewise no published file may point at a private repository: a
    visitor gets a 404, and the reference itself discloses internal structure.
    """
    for f in files:
        rel = f.relative_to(ROOT).as_posix()
        if rel.startswith(AGENT_CONFIG) or f.name in AGENT_FILES:
            problems.append(f"{rel}: agent/editor config must not be tracked in this public repo")
            continue
        if rel == "scripts/validate-site.py" or f.suffix not in TEXT_SUFFIXES or not f.is_file():
            continue
        for n, line in enumerate(f.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            m = PRIVATE_REF.search(line)
            if m:
                problems.append(f"{rel}:{n}: references private repository {m.group(0)!r}")


def check_no_docs(files: list[Path]) -> None:
    stray = sorted(f.relative_to(ROOT).as_posix() for f in files if f.relative_to(ROOT).parts[0] == "docs")
    if stray:
        problems.append("docs/: documentation is not published from this repo — " + ", ".join(stray))


def check_json_fields_are_escaped() -> None:
    """claude-agents#155: catalog/factory JSON reaches innerHTML, so a field must go through esc()."""
    page = ROOT / "index.html"
    for n, line in enumerate(page.read_text().splitlines(), 1):
        for m in re.finditer(r"\$\{\s*([cp])\.(\w+)\s*\}", line):
            problems.append(f"index.html:{n}: ${{{m.group(1)}.{m.group(2)}}} is interpolated without esc()")


# The one third-party script a page may load: Google's tag, which is versioned by Google and
# cannot carry an integrity hash. Everything else is served from this repo (claude-agents#152).
ALLOWED_SCRIPT_HOSTS = ("https://www.googletagmanager.com/gtag/js",)
SCRIPT_SRC = re.compile(r"<script\b[^>]*\bsrc=\"([^\"]+)\"", re.I)


def check_pinned_assets(files: list[Path]) -> None:
    """claude-agents#152: no Play CDN, no unpinned third-party script, a CSP on every page."""
    for html in [f for f in files if f.suffix == ".html"]:
        rel = html.relative_to(ROOT).as_posix()
        body = html.read_text(encoding="utf-8", errors="ignore")
        for src in SCRIPT_SRC.findall(body):
            if src.startswith(("http://", "https://", "//")) and not src.startswith(ALLOWED_SCRIPT_HOSTS):
                problems.append(f"{rel}: third-party script {src!r}: self-host it under assets/vendor/ "
                                f"(pinned version) instead")
        if "cdn.tailwindcss.com" in body:
            problems.append(f"{rel}: Tailwind Play CDN: link /assets/css/site.css (scripts/build-css.sh)")
        if "@latest" in body:
            problems.append(f"{rel}: an @latest asset URL: pin the version")
        if 'http-equiv="Content-Security-Policy"' not in body:
            problems.append(f"{rel}: no Content-Security-Policy meta tag")


def check_css_fresh() -> None:
    """9. assets/css/site.css is what scripts/build-css.sh wrote for the current pages (claude-agents#152)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("css_stamp", ROOT / "scripts" / "css_stamp.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    problems.extend(mod.problems())


def main() -> int:
    files = tracked()
    check_parsers(files)
    check_catalog()
    check_duplicates(files)
    check_local_assets(files)
    check_nothing_private(files)
    check_no_docs(files)
    check_json_fields_are_escaped()
    check_pinned_assets(files)
    check_css_fresh()

    if problems:
        print(f"validate-site: {len(problems)} problem(s)\n", file=sys.stderr)
        for p in problems:
            print(f"  ✗ {p}", file=sys.stderr)
        return 1

    print(f"validate-site: OK — {len(files)} tracked file(s) checked.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
