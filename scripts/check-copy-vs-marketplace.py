#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 StigReady
# SPDX-License-Identifier: LicenseRef-StigReady-Proprietary
"""Public copy must match production (claude-agents decision 0114).

Modes:

  --mode pr       (L1) The site in --site against the live Marketplace snapshot (--snapshot). Fails when a live-Public
                  product is shown as coming soon or missing, a product is shown as purchasable but is not live
                  Public, a line is called "coming soon" while it has live-Public listings, a price differs from the
                  live price, a region is claimed that no live listing of that line has, or a row's version or name
                  differs from its live listing. A missing, unparseable or stale snapshot fails (fail closed).
  --mode trust-root
                  config/trust-root-paths (what judges pull requests) against config/trust-root.sha256: names every
                  entry that differs (--write regenerates the manifest). L2, the removal gate, is a separate PR.
  --mode drift    (L3) Fetches the live site (--site-url, every page of its sitemap, the scripts and stylesheets they
                  load, and /catalog.json), the public role
                  READMEs and the stigvalidated pages (config/copy-truth-sources.yml), checks them against the
                  snapshot (and each role README's release against its newest v* tag), writes a Markdown report and,
                  with --issue, opens, updates or closes the one `copy-drift` issue.

What a page shows is what it renders: scripts/render/render.mjs (Node, jsdom pinned in scripts/render/package-lock.json)
runs each page's own scripts against its catalog.json in a locked-down process, then a separate process that runs no
page code decides from the resulting markup and the page's styles which rows, AWS Marketplace links and text a visitor
can see; anything it cannot evaluate counts as not visible. A product counts as purchasable only if a visible link to
its listing is rendered.

Exit 0: no finding. 1: findings. 2: cannot check (bad input, stale or empty snapshot, fetch failure, no renderer): never
a pass.

The snapshot (schema stigready-marketplace-live/1) is written by stigready's `marketplace-live-snapshot` Cairn job
(granted marketplace-ro) to this repo's `live/marketplace` branch. Pull request runs get no credentials, so they read
that file instead of Marketplace; the Cairn job runs this script and the snapshot from the base branch, never the PR's.
Any repo writer can push a branch, so the branch itself proves nothing: the snapshot is trusted only with an SSH
signature (marketplace-live.json.sig, namespace stigready-marketplace-snapshot) by a key listed in
config/snapshot-signers of the checker's own tree (the base). No key, no signature or a bad one: exit 2.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import html
import html.parser
import json
import os
import re
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

SCHEMA = "stigready-marketplace-live/1"
SNAPSHOT_SIGNERS_PATH = "config/snapshot-signers"
SNAPSHOT_NAMESPACE = "stigready-marketplace-snapshot"
SNAPSHOT_SIGNER_ID = "snapshot@stigready"
SNAPSHOT_KEY_TYPES = ("ssh-ed25519",)
RENDERER = Path(__file__).resolve().parent / "render" / "render.mjs"
# The snapshot key list of the tree this checker came from (the base, in the PR jobs).
DEFAULT_SNAPSHOT_SIGNERS = Path(__file__).resolve().parent.parent / SNAPSHOT_SIGNERS_PATH
REPO = "stigready/stigready-web"
PP_PREFIX = "https://aws.amazon.com/marketplace/pp/"

LINES = {"stigready": "StigReady Base", "stigapplied": "StigReady Applied"}
# A line-name mention in copy. "Base" and "Applied" alone count only when capitalised, as the site writes them.
LINE_RE = re.compile(r"\b(?:StigReady\s+)?(Base|Applied)\b")
LINE_OF = {"Base": "stigready", "Applied": "stigapplied"}
WITHHELD_RE = re.compile(
    r"coming\s+soon|not\s+yet\s+(?:on|available|purchasable|live)|planned\s+price|not\s+(?:yet\s+)?available"
    r"|unavailable|\bnot\s+yet\b", re.I)
PURCHASABLE_RE = re.compile(r"\b(?:is|are)\s+(?:now\s+)?(?:on|live\s+on|available\s+on)\s+AWS\s+Marketplace", re.I)
PRICE_RE = re.compile(r"\$\s?(\d+(?:\.\d+)?)\s*(?:<[^>]*>\s*)*/\s*(hr|hour|yr|year)\b", re.I)
REGION_RE = re.compile(r"\b(?:us|eu|ap|ca|sa|me|af|il|mx)-(?:gov-)?(?:east|west|north|south|central|northeast|"
                       r"northwest|southeast|southwest)-\d\b")


class CannotCheck(Exception):
    """Production or site state could not be read: exit 2, never a pass."""


# ---------------------------------------------------------------------------------------------------------- site text

class _Text(html.parser.HTMLParser):
    """Visible text plus JSON-LD (FAQ answers are public in search results). Other scripts and styles are dropped."""

    BLOCK = {"p", "div", "li", "td", "th", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "dd", "dt", "section", "br",
             "header", "footer", "article", "table", "ul", "ol", "title", "meta"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0
        self._ld = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script":
            self._ld = (a.get("type") or "").lower() == "application/ld+json"
            if not self._ld:
                self._skip += 1
        elif tag == "style":
            self._skip += 1
        elif tag == "meta" and (a.get("name") in ("description", "twitter:description")
                                or a.get("property") in ("og:description",)):
            self.parts.append("\n" + (a.get("content") or "") + "\n")
        if tag in self.BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag == "script":
            if self._ld:
                self._ld = False
            else:
                self._skip = max(0, self._skip - 1)
        elif tag == "style":
            self._skip = max(0, self._skip - 1)
        if tag in self.BLOCK:
            self.parts.append("\n")

    def handle_data(self, data):
        if self._skip:
            return
        if self._ld:
            try:
                self.parts.append("\n" + "\n".join(_ld_strings(json.loads(data))) + "\n")
            except ValueError:
                pass
            return
        self.parts.append(data)


def _ld_strings(node) -> list[str]:
    if isinstance(node, dict):
        return [s for k, v in node.items() if k in ("name", "text", "description", "@graph", "mainEntity",
                                                     "acceptedAnswer", "offers") for s in _ld_strings(v)]
    if isinstance(node, list):
        return [s for v in node for s in _ld_strings(v)]
    return [node] if isinstance(node, str) else []


def page_text(raw: str) -> str:
    p = _Text()
    p.feed(raw)
    return re.sub(r"[ \t\r\f\v]+", " ", "".join(p.parts))


class _Meta(_Text):
    """Only what a visitor sees outside the rendered body: meta descriptions and JSON-LD (search results)."""

    def handle_data(self, data):
        if self._ld and not self._skip:
            super().handle_data(data)


def meta_text(raw: str) -> str:
    p = _Meta()
    p.feed(raw)
    return re.sub(r"[ \t\r\f\v]+", " ", "".join(p.parts))


def sentences(text: str) -> list[str]:
    out = []
    for block in text.split("\n"):
        block = block.strip()
        if block:
            out += [s.strip() for s in re.split(r"(?<=[.!?])\s+(?=[A-Z\"(])", block) if s.strip()]
    return out


def default_line(rel: str) -> str | None:
    return "stigapplied" if rel.startswith("applied/") or rel == "stigapplied.html" else None


def segments(sentence: str, default: str | None):
    """(line, text) pieces: text after a line-name mention belongs to that line until the next mention."""
    marks = list(LINE_RE.finditer(sentence))
    if not marks:
        return [(default, sentence)]
    out = []
    if marks[0].start() > 0:
        out.append((default, sentence[:marks[0].start()]))
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(sentence)
        out.append((LINE_OF[m.group(1)], sentence[m.start():end]))
    return out


def claims_from_text(rel: str, text: str) -> list[dict]:
    """Availability, price and region claims in one page's (or README's) text, each tied to a line where it can be."""
    claims = []
    default = default_line(rel)
    for s in sentences(text):
        segs = segments(s, default)
        lines_in = {ln for ln, _ in segs if ln}
        if WITHHELD_RE.search(s) and not re.search(r"stigvalidated", s, re.I):
            # The line named just before the withheld phrase ("Base is on Marketplace; Applied is coming soon" withholds
            # Applied only). A phrase before any line name belongs to the page's own line, or, on a page with none, to
            # every line the sentence names.
            hit = {ln for ln, seg in segs if ln and WITHHELD_RE.search(seg)}
            if any(ln is None and WITHHELD_RE.search(seg) for ln, seg in segs):
                hit |= {default} if default else lines_in
            for ln in sorted(hit):
                claims.append({"kind": "withheld", "line": ln, "page": rel, "text": s[:240]})
        if PURCHASABLE_RE.search(s):
            for ln, seg in segs:
                if ln and PURCHASABLE_RE.search(seg):
                    claims.append({"kind": "purchasable", "line": ln, "page": rel, "text": s[:240]})
        for ln, seg in segs:
            for m in PRICE_RE.finditer(seg):
                unit = "hourly" if m.group(2).lower() in ("hr", "hour") else "annual"
                claims.append({"kind": "price", "line": ln, "unit": unit, "value": _num(m.group(1)), "page": rel,
                               "text": s[:240]})
            for m in REGION_RE.finditer(seg):
                claims.append({"kind": "region", "line": ln, "region": m.group(0), "page": rel, "text": s[:240]})
    return claims


def _num(s: str) -> str:
    return format(float(s), "g")


# ---------------------------------------------------------------------------------------------------------- site model

def ident(p: dict) -> tuple:
    return (p.get("line"), p.get("profile"), p.get("os_key"), p.get("arch"))


def ident_str(k: tuple) -> str:
    return "/".join(str(x) for x in k)


def site_pages(root: Path) -> dict[str, str]:
    pages = {}
    for f in sorted(root.rglob("*.html")):
        parts = f.relative_to(root).parts
        rel = f.relative_to(root).as_posix()
        if rel.startswith(("cinc/", "scripts/", "assets/", "node_modules/")) or any(
                part.startswith(".") or part == "node_modules" for part in parts) or f.is_symlink():
            continue
        pages[rel] = f.read_text(encoding="utf-8", errors="replace")
    return pages


# Page scripts run in their own Node process (render.mjs `run`): code generation from strings off, intrinsics frozen,
# the permission model on (read only: the site and the renderer; no child processes, workers or writes). Its output is
# authenticated with a fresh key passed on stdin; what is visible is then decided by a second process that never runs
# page code (render.mjs `eval`).
RUN_FLAGS = ("--disallow-code-generation-from-strings", "--frozen-intrinsics", "--no-warnings", "--permission")


def node_env() -> dict[str, str]:
    """The renderer's whole environment: PATH only. Page scripts run in that process, and Node's permission model does
    not limit environment variables, so nothing else (GH_TOKEN in the drift job, AWS or Vault variables) may reach it."""
    return {"PATH": os.environ.get("PATH") or os.defpath}


def render(root: Path, pages: list[str], node: str, renderer: Path) -> list[dict]:
    """Run the pages' own scripts, then evaluate what a visitor sees (scripts/render/render.mjs). No renderer: cannot
    check."""
    if not renderer.is_file():
        raise CannotCheck(f"renderer {renderer} missing")
    root, rdir = root.resolve(), renderer.resolve().parent
    reads = [f"--allow-fs-read={root}", f"--allow-fs-read={rdir}"]
    key = os.urandom(32)
    try:
        p = subprocess.run([node, *RUN_FLAGS, *reads, str(renderer), "run", str(root), *pages],
                           input=key.hex().encode(), capture_output=True, timeout=600, env=node_env())
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CannotCheck(f"renderer could not run ({node}): {type(exc).__name__}") from exc
    if p.returncode != 0:
        raise CannotCheck(f"renderer failed (rc {p.returncode}): {p.stderr.decode(errors='replace').strip()[-300:]}")
    mac, _, body = p.stdout.partition(b"\n")
    want = hmac.new(key, body, hashlib.sha256).hexdigest().encode()
    if not hmac.compare_digest(mac, want):
        raise CannotCheck("renderer output is not authentic: a page changed what the renderer reports")
    try:
        got = [pg.get("page") for pg in json.loads(body)["pages"]]
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise CannotCheck("renderer output unreadable") from exc
    if got != list(pages):
        raise CannotCheck("renderer output is for other pages than were asked for")
    try:
        e = subprocess.run([node, "--permission", *reads, str(renderer), "eval", str(root)],
                           input=body, capture_output=True, timeout=600, env=node_env())
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CannotCheck(f"renderer could not evaluate ({node}): {type(exc).__name__}") from exc
    if e.returncode != 0:
        raise CannotCheck(f"renderer evaluation failed (rc {e.returncode}): "
                          f"{e.stderr.decode(errors='replace').strip()[-300:]}")
    try:
        out = json.loads(e.stdout)
        assert isinstance(out, list) and len(out) == len(pages)
        assert [r.get("page") for r in out] == list(pages)
        return out
    except (ValueError, AssertionError, AttributeError) as exc:
        raise CannotCheck("renderer output unreadable") from exc


TBODY_LINE = {"base-tbody": "stigready", "applied-tbody": "stigapplied"}
# The catalog's one location: the page that carries the Base and Applied tables. A listing counts only from its row
# there; the same table or link on any other page (an archive, a copy, a decoy) counts for nothing.
CATALOG_PAGE = "index.html"


def is_catalog_page(rel: str, raw: str) -> bool:
    return rel == CATALOG_PAGE or "catalog.json" in raw


def _row_matches(p: dict, cells: list[str]) -> bool:
    if len(cells) < 2 or not cells[0].startswith(str(p.get("os"))) or cells[1] != p.get("arch"):
        return False
    rest = cells[0][len(str(p.get("os"))):].strip()
    if rest not in ("", "BYOL"):
        return False
    return p.get("line") != "stigapplied" or (len(cells) > 2 and cells[2] == p.get("benchmark"))


def load_site(root: Path, node: str = "node", renderer: Path = RENDERER) -> dict:
    """What a visitor sees: each catalog product's rendered state on the catalog page, and the claims in every page's
    text. Claims are read from all of a page's text, visible or not: hiding a sentence never removes a claim."""
    cat_path = root / "catalog.json"
    try:
        if cat_path.is_symlink():
            raise ValueError("symlink")
        catalog = json.loads(cat_path.read_text(encoding="utf-8"))
        products = catalog["products"]
        assert isinstance(products, list)
    except (OSError, ValueError, KeyError, AssertionError) as exc:
        raise CannotCheck(f"{cat_path}: unreadable catalog ({type(exc).__name__})") from exc
    pages = site_pages(root)
    rendered = render(root, list(pages), node, renderer) if pages else []
    claims, linked, rows, errors, unevaluable = [], [], [], [], []
    for r in rendered:
        rel = r["page"]
        claims += claims_from_text(rel, meta_text(pages[rel]) + "\n" + r.get("text_all", r.get("text", "")))
        if is_catalog_page(rel, pages[rel]):
            unevaluable += [f"{rel}: {why}" for why in r.get("unevaluable") or []]
        errors += [f"{rel}: {e}" for e in r.get("errors") or []]
        if rel != CATALOG_PAGE:
            continue
        page_rows = r.get("rows") or []
        # A listing link counts only where a visitor can tell what it is for: visible, in a visible row of a catalog
        # table whose own cells name the product (a row whose name is made invisible does not, even if its link is).
        for lk in r.get("links") or []:
            i = lk.get("row")
            if lk.get("visible") and isinstance(i, int) and 0 <= i < len(page_rows):
                row = page_rows[i]
                if row.get("visible") and row.get("tbody") in TBODY_LINE:
                    linked.append((lk["href"], row))
        rows += [(rel, row) for row in page_rows if row.get("visible") and row.get("tbody") in TBODY_LINE]
    withheld_lines = {c["line"] for c in claims if c["kind"] == "withheld"}
    state = {}
    for p in products:
        url = p.get("marketplace_url")
        mine = [row for _, row in rows if TBODY_LINE[row["tbody"]] == p.get("line") and _row_matches(p, row["cells"])]
        if isinstance(url, str) and url.startswith(PP_PREFIX) and any(
                href == url and TBODY_LINE[row["tbody"]] == p.get("line") and _row_matches(p, row["cells"])
                for href, row in linked):
            row = "purchasable"
        elif any(WITHHELD_RE.search(r["text"]) for r in mine):
            row = "withheld"
        elif mine:
            row = "neutral"
        else:
            row = "absent"
        shown = row
        if row == "neutral" and p.get("line") in withheld_lines:
            shown = "withheld"
        state[ident(p)] = {"row": row, "shown": shown, "product": p}
    return {"rows": state, "claims": claims, "render_errors": errors, "unevaluable": unevaluable, "pages": pages}


# ------------------------------------------------------------------------------------------------------------ snapshot

def verify_snapshot(raw: bytes, path: Path, sig: Path, signers: Path) -> None:
    """The snapshot must carry an SSH signature by a key in config/snapshot-signers (read from the checker's own tree,
    the base). The live/marketplace branch is pushable by any repo writer, so the branch alone is no proof."""
    try:
        allowed, refused = allowed_signers(signers.read_text(encoding="utf-8") if not signers.is_symlink() else "",
                                           SNAPSHOT_SIGNER_ID, SNAPSHOT_NAMESPACE, SNAPSHOT_KEY_TYPES)
    except OSError:
        allowed, refused = "", []
    if not allowed:
        raise CannotCheck(f"{signers} lists no snapshot key" + (f" (refused: {'; '.join(refused)})" if refused else "")
                          + ": the snapshot cannot be authenticated, production state unknown")
    try:
        if sig.is_symlink() or not sig.is_file():
            raise CannotCheck(f"snapshot {path}: no signature {sig.name}: production state unknown")
    except OSError as exc:
        raise CannotCheck(f"snapshot {path}: signature unreadable ({type(exc).__name__}): production state unknown") \
            from exc
    ok, err = ssh_verify(allowed, SNAPSHOT_SIGNER_ID, SNAPSHOT_NAMESPACE, sig, raw)
    if not ok:
        raise CannotCheck(f"snapshot {path}: signature does not verify ({err})"
                          + (f" (refused key lines: {'; '.join(refused)})" if refused else "")
                          + ": production state unknown")


def load_snapshot(path: Path, now: dt.datetime, max_age_hours: float, sig: Path | None = None,
                  signers: Path | None = None) -> dict:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise CannotCheck(f"snapshot {path}: unreadable ({type(exc).__name__}): production state unknown") from exc
    verify_snapshot(raw, path, sig or path.with_name(path.name + ".sig"), signers or DEFAULT_SNAPSHOT_SIGNERS)
    try:
        snap = json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise CannotCheck(f"snapshot {path}: unreadable ({type(exc).__name__}): production state unknown") from exc
    if not isinstance(snap, dict) or snap.get("schema") != SCHEMA or not isinstance(snap.get("products"), list):
        raise CannotCheck(f"snapshot {path}: not {SCHEMA}: production state unknown")
    try:
        gen = dt.datetime.fromisoformat(str(snap["generated"]).replace("Z", "+00:00"))
    except (KeyError, ValueError) as exc:
        raise CannotCheck(f"snapshot {path}: no valid `generated` time") from exc
    if gen.tzinfo is None:
        gen = gen.replace(tzinfo=dt.timezone.utc)
    age = (now - gen).total_seconds() / 3600
    if age > max_age_hours or age < -1:
        raise CannotCheck(f"snapshot generated {snap['generated']} is {age:.1f} h old (limit {max_age_hours:g} h): "
                          "production state unknown")
    if not any(p.get("visibility") == "Public" for p in snap["products"] if isinstance(p, dict)):
        # An empty Catalog read would make every "coming soon" pass: the incident's direction. Never a pass.
        raise CannotCheck(f"snapshot generated {snap['generated']} lists no Public listing: production state unknown")
    return snap


def norm_os(s: str) -> str:
    s = re.sub(r"linux|lts|\(.*?\)", " ", (s or "").lower())
    return re.sub(r"\s+", " ", s).strip()


PROFILE_WORDS = {"base": "stig disk layout", "cis-l1": "level 1", "cis-l2": "level 2", "stig": "stig"}


def name_mismatch(p: dict, title: str) -> str | None:
    t = (title or "").lower()
    want = [LINES.get(p.get("line"), "").lower(), norm_os(p.get("os", "")), PROFILE_WORDS.get(p.get("profile"), ""),
            f"({p.get('arch')})" if p.get("line") == "stigapplied" else str(p.get("arch"))]
    tn = norm_os(title) + " " + t
    missing = [w for w in want if w and w not in tn]
    return f"live title {title!r} lacks {missing}" if missing else None


# --------------------------------------------------------------------------------------------------------------- L1

def check_pr(site: dict, snap: dict) -> tuple[list[str], list[str]]:
    fails, warns = [], []
    live = {}
    for lp in snap["products"]:
        if lp.get("visibility") == "Public":
            live[(lp.get("line"), lp.get("profile"), lp.get("os_key"), lp.get("arch"))] = lp
    live_lines = {k[0] for k in live}
    rows = site["rows"]
    for k, lp in sorted(live.items(), key=lambda kv: ident_str(kv[0])):
        r = rows.get(k)
        if r is None or r["shown"] == "absent":
            fails.append(f"MISSING {ident_str(k)}: live Public ({lp.get('product_id')}) but not shown on the site")
            continue
        if r["shown"] == "withheld":
            fails.append(f"WITHHELD {ident_str(k)}: live Public ({lp.get('product_id')}) but shown as coming soon")
        elif r["row"] != "purchasable":
            # Rendered, but no visible link to its listing: a script or style change can hide every link while the
            # row still looks fine (the review's `if (false && ...)` and `display:none` cases).
            fails.append(f"NOT-LINKED {ident_str(k)}: live Public ({lp.get('product_id')}) but the site shows no "
                         "visible link to its listing")
        p = r["product"]
        versions = [str(v).lstrip("v") for v in lp.get("versions") or []]
        if versions and p.get("version") and str(p["version"]).lstrip("v") not in versions:
            fails.append(f"VERSION {ident_str(k)}: site {p['version']}, live listing {lp.get('product_id')} has "
                         f"{', '.join(lp.get('versions'))}")
        if lp.get("title"):
            why = name_mismatch(p, lp["title"])
            if why:
                fails.append(f"NAME {ident_str(k)}: site {p.get('os')!r}; {why}")
    if snap.get("unidentified"):
        fails.append(f"UNIDENTIFIED {snap['unidentified']} live Public listing(s) the snapshot could not match to a "
                     "catalog product: the site cannot be checked against them")
    warns += [f"RENDER {e}" for e in site.get("render_errors") or []]
    # A catalog page the renderer cannot evaluate is never a pass.
    fails += [f"UNEVALUABLE {u}" for u in site.get("unevaluable") or []]
    for k, r in sorted(rows.items(), key=lambda kv: ident_str(kv[0])):
        if r["row"] == "purchasable" and k not in live:
            fails.append(f"NOT-LIVE {ident_str(k)}: shown as purchasable but no live Public listing")
    seen = set()
    for c in site["claims"]:
        ln = c.get("line")
        if c["kind"] == "withheld" and ln in live_lines:
            key = ("w", ln, c["page"], c["text"])
            if key not in seen:
                seen.add(key)
                n = sum(1 for k in live if k[0] == ln)
                fails.append(f"WITHHELD-TEXT {c['page']}: {LINES.get(ln, ln)} has {n} live Public listings, "
                             f"copy says: {c['text']!r}")
        elif c["kind"] == "purchasable" and ln and ln not in live_lines:
            fails.append(f"NOT-LIVE-TEXT {c['page']}: {LINES.get(ln, ln)} has no live Public listing, copy says: "
                         f"{c['text']!r}")
        elif c["kind"] == "price" and ln:
            if ln not in live_lines:
                continue  # a planned price for a line not yet on sale is not a production claim
            price = ((snap.get("prices") or {}).get(ln) or {}).get(f"{c['unit']}_usd")
            if price is None:
                key = ("p", ln, c["unit"], c["value"])
                if key not in seen:
                    seen.add(key)
                    warns.append(f"PRICE-UNVERIFIED {LINES.get(ln, ln)} {c['unit']} ${c['value']}: the snapshot has "
                                 f"no live price ({(snap.get('price_source') or 'not read')})")
            elif _num(str(price)) != c["value"]:
                fails.append(f"PRICE {c['page']}: {LINES.get(ln, ln)} {c['unit']} ${c['value']} on the site, "
                             f"${_num(str(price))} live: {c['text']!r}")
        elif c["kind"] == "region" and ln:
            have = {rg for k, lp in live.items() if k[0] == ln for rg in lp.get("regions") or []}
            if c["region"] not in have:
                fails.append(f"REGION {c['page']}: {LINES.get(ln, ln)} claims {c['region']}, live listings have "
                             f"{sorted(have) or 'none'}")
    return fails, warns


# -------------------------------------------------------------------------------------------------------- signatures

HREF_RE = re.compile(r"""<(?:link|script)\b[^>]*\b(?:href|src)\s*=\s*["']([^"']+)["'][^>]*>""", re.I)


def _split_unquoted(text: str, seps: str) -> list[str]:
    """Split on any of seps outside double quotes, dropping empty pieces."""
    out, cur, q = [], "", False
    for ch in text:
        if ch == '"':
            q = not q
        if ch in seps and not q:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    return [x for x in out + [cur] if x]


VALIDITY_RE = re.compile(r'valid-(?:after|before)="\d{8}(?:\d{4}(?:\d{2})?)?Z?"')


def allowed_signers(text: str, principal: str, namespace: str, key_types: tuple[str, ...]) -> tuple[str, list[str]]:
    """(lines that count, rewritten canonically; why each other key line does not count). A line counts only when its
    principal is exactly `principal`, its options name exactly this namespace, carry no cert-authority (a CA would let
    any key it certifies sign), and its key type is one of key_types. valid-after and valid-before are kept, so
    ssh-keygen enforces them; any other option (verify-required included) refuses the line. Nothing is dropped
    silently: every refused line is named."""
    keep, refused = [], []
    for n, line in enumerate(text.splitlines(), 1):
        f = _split_unquoted(line.strip(), " \t")
        if not f or f[0].startswith("#"):
            continue
        why = None
        opts = [o.strip() for o in _split_unquoted(f[1], ",")] if len(f) >= 4 else []
        low = [o.lower() for o in opts]
        if len(f) < 4 or f[0] != principal:
            why = f"not principal {principal} with options"
        elif f[2] not in key_types:
            why = f"key type {f[2]} is not one of {', '.join(key_types)}"
        elif "cert-authority" in low:
            why = "cert-authority is refused"
        elif f'namespaces="{namespace}"' not in low:
            why = f'options do not name namespaces="{namespace}"'
        elif not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", f[3]):
            why = "the key is not base64"
        else:
            other = [o for o, lo in zip(opts, low) if lo != f'namespaces="{namespace}"' and not VALIDITY_RE.fullmatch(lo)]
            if other:
                why = f"unsupported option(s) {', '.join(other)}"
        if why:
            refused.append(f"line {n}: {why}")
            continue
        validity = [o for o in opts if VALIDITY_RE.fullmatch(o.lower())]
        options = ",".join(['namespaces="' + namespace + '"'] + validity)
        keep.append(f"{principal} {options} {f[2]} {f[3]}")
    return "\n".join(keep) + ("\n" if keep else ""), refused




def ssh_verify(allowed: str, principal: str, namespace: str, sig: Path, data: bytes) -> tuple[bool, str]:
    """(verified, ssh-keygen's message). ssh-keygen missing or hung: cannot check (exit 2), never a pass or a finding."""
    try:
        with tempfile.TemporaryDirectory() as d:
            af = Path(d) / "allowed_signers"
            af.write_text(allowed)
            p = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(af), "-I", principal, "-n", namespace,
                                "-s", str(sig)], input=data, capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CannotCheck(f"ssh-keygen could not verify a signature ({type(exc).__name__}): the signature is "
                          "unchecked") from exc
    return p.returncode == 0, p.stderr.decode(errors="replace").strip()[:200]


# ------------------------------------------------------------------------------------------------------- trust root

TRUST_ROOT_PATHS = "config/trust-root-paths"
TRUST_ROOT_MANIFEST = "config/trust-root.sha256"
_SKIP_PARTS = {"node_modules", "__pycache__", ".render", ".ci-venv", ".git"}


SYMLINK = "symlink"


def _block(lines: list[str], i: int) -> list[str]:
    """Line i and every following line indented deeper than it (blank lines included), without the trailing comments
    and blank lines that lead into the next sibling."""
    ind = len(lines[i]) - len(lines[i].lstrip())
    j = i + 1
    while j < len(lines) and (not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip()) > ind
                              or (lines[j].lstrip().startswith("#") and len(lines[j]) - len(lines[j].lstrip()) > ind)):
        j += 1
    block = lines[i:j]
    while block and (not block[-1].strip() or block[-1].lstrip().startswith("#")):
        block.pop()
    return block


def yml_block(cairn_yml: str, frag: str) -> str | None:
    """A part of .cairn.yml named by an entry fragment: `<job>` (the job), `<job>/<step>` (one step of that job), or
    `triggers/<key>` (one trigger, such as the schedule). Text, so the checker needs no YAML library."""
    lines = cairn_yml.splitlines()
    if frag.startswith("triggers/"):
        key = frag.split("/", 1)[1]
        top = next((i for i, ln in enumerate(lines) if ln == "triggers:"), None)
        if top is None:
            return None
        for i in range(top + 1, len(lines)):
            if lines[i].strip() and not lines[i].startswith((" ", "#")):
                break
            if re.fullmatch(rf"  {re.escape(key)}:.*", lines[i]):
                return "\n".join(_block(lines, i)) + "\n"
        return None
    job, _, step = frag.partition("/")
    for i, ln in enumerate(lines):
        if re.fullmatch(rf"  - name: {re.escape(job)}\s*", ln):
            j = i + 1
            while j < len(lines) and not re.match(r"  - name: |\S", lines[j]):
                j += 1
            block = lines[i:j]
            while block and (not block[-1].strip() or block[-1].lstrip().startswith("#")):
                block.pop()
            if not step:
                return "\n".join(block) + "\n"
            for k, sl in enumerate(block):
                if re.fullmatch(rf"\s+- name: {re.escape(step)}\s*", sl) and k > 0:
                    return "\n".join(_block(block, k)) + "\n"
            return None
    return None


def _digest(raw) -> str:
    if raw is None:
        return "missing"
    if raw == SYMLINK:
        return SYMLINK
    return hashlib.sha256(raw).hexdigest()


def trust_root_entries(read, listing, list_text: str) -> dict[str, str]:
    """Entry -> sha256 for every entry of config/trust-root-paths: a file, a directory glob ending in /** (every file
    under it, each its own entry), or .cairn.yml#<fragment> (see yml_block). `read(path)` returns bytes, None (missing)
    or SYMLINK; `listing(prefix)` returns the files and links under prefix. The list itself is always an entry. A
    missing entry is "missing"; a link is "symlink", which is never accepted (it would hash nothing of its target)."""
    out: dict[str, str] = {}
    entries = [TRUST_ROOT_PATHS]
    for ln in list_text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        entries.append(ln.split(" #", 1)[0].strip())
    for e in entries:
        if "#" in e:
            path, frag = e.split("#", 1)
            raw = read(path)
            if raw is None or raw == SYMLINK:
                out[e] = _digest(raw)
                continue
            block = yml_block(raw.decode("utf-8", "replace"), frag)
            out[e] = hashlib.sha256(block.encode()).hexdigest() if block is not None else "missing"
        elif e.endswith("/**"):
            files = [f for f in listing(e[:-3]) if not _SKIP_PARTS & set(f.split("/"))]
            for f in sorted(files):
                out[f] = _digest(read(f))
            if not files:
                out[e] = "missing"
        else:
            out[e] = _digest(read(e))
    return out


def trust_root_of_dir(root: Path, list_root: Path | None = None) -> dict[str, str]:
    """The trust root of the tree at root, by the entry list of list_root (default: root itself)."""
    def read(rel):
        f = root / rel
        if f.is_symlink():
            return SYMLINK
        return f.read_bytes() if f.is_file() else None

    def listing(prefix):
        d = root / prefix
        if not d.is_dir() or d.is_symlink():
            return []
        return [q.relative_to(root).as_posix() for q in d.rglob("*") if q.is_symlink() or q.is_file()]
    lst_file = (list_root or root) / TRUST_ROOT_PATHS
    if lst_file.is_symlink() or not lst_file.is_file():
        raise CannotCheck(f"{TRUST_ROOT_PATHS} missing: the trust root is unknown")
    return trust_root_entries(read, listing, lst_file.read_text(encoding="utf-8"))


def trust_root_manifest(root: Path) -> dict[str, str]:
    f = root / TRUST_ROOT_MANIFEST
    if not f.is_file() or f.is_symlink():
        raise CannotCheck(f"{TRUST_ROOT_MANIFEST} missing: the trust root cannot be compared")
    out = {}
    for ln in f.read_text(encoding="utf-8").splitlines():
        m = re.fullmatch(r"([0-9a-f]{64}|missing)  (\S+)", ln)  # a symlink is never written, so never matches
        if m:
            out[m.group(2)] = m.group(1)
    return out


def trust_root_render(entries: dict[str, str]) -> str:
    return ("# The trust root of the copy-truth checks (decision 0114): what judges a PR. Generated by\n"
            "#   python3 scripts/check-copy-vs-marketplace.py --mode trust-root --write\n"
            "# from config/trust-root-paths. A PR that changes this file changes what judges every later PR:\n"
            "# review/security reviews each changed line. CINC web-copy-truth-08 (validate, this PR's own code) names\n"
            "# them; copy-truth runs the same comparison with the BASE's checker, list and manifest.\n"
            + "".join(f"{v}  {k}\n" for k, v in sorted(entries.items())))


# --------------------------------------------------------------------------------------------------------------- L3

def _get(url: str, token: str | None = None, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "stigready-copy-drift/1"})
    if token and url.startswith("https://api.github.com/"):
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CannotCheck(f"fetch {url}: {type(exc).__name__}") from exc


def fetch_site(site_url: str, into: Path) -> list[str]:
    host = urllib.parse.urlparse(site_url).netloc
    sm = _get(site_url.rstrip("/") + "/sitemap.xml").decode("utf-8", "replace")
    urls = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", sm)
    got = []
    for u in [site_url.rstrip("/") + "/"] + urls:
        pu = urllib.parse.urlparse(u)
        if pu.netloc != host:
            continue
        rel = pu.path.lstrip("/")
        rel = rel + "index.html" if rel == "" or rel.endswith("/") else rel
        if not rel.endswith(".html"):
            rel += "/index.html"
        dest = into / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        body = _get(u)
        dest.write_bytes(body)
        got.append(u)
        # The page renders with its own scripts and styles: fetch every local one it loads (once).
        for ref in HREF_RE.findall(body.decode("utf-8", "replace")):
            au = urllib.parse.urlparse(urllib.parse.urljoin(u, ref))
            if au.netloc != host or not au.path.endswith((".css", ".js", ".mjs", ".json")):
                continue
            adest = into / au.path.lstrip("/")
            if not adest.exists() and into.resolve() in adest.resolve().parents:
                adest.parent.mkdir(parents=True, exist_ok=True)
                adest.write_bytes(_get(f"{au.scheme}://{au.netloc}{au.path}"))
    for extra in ("catalog.json", "stigforge-factory.json"):
        try:
            (into / extra).write_bytes(_get(site_url.rstrip("/") + "/" + extra))
        except CannotCheck:
            if extra == "catalog.json":
                raise
    return got


def _vkey(t: str):
    return tuple(int(x) for x in re.findall(r"\d+", t))


def check_readmes(sources: dict, snap: dict, token: str | None) -> tuple[list[str], list[str]]:
    fails, read = [], []
    live_lines = {lp.get("line") for lp in snap["products"] if lp.get("visibility") == "Public"}
    for repo in sources.get("role_repos") or []:
        readme = _get(f"https://raw.githubusercontent.com/{repo}/HEAD/README.md").decode("utf-8", "replace")
        tags = json.loads(_get(f"https://api.github.com/repos/{repo}/tags?per_page=100", token))
        vt = sorted((t["name"] for t in tags if re.fullmatch(r"v\d+(\.\d+)*", t.get("name", ""))), key=_vkey)
        read.append(f"https://github.com/{repo}")
        claimed = set(re.findall(r"release \*\*`v?(\d+(?:\.\d+)+)`\*\*", readme))
        claimed |= set(re.findall(r"version:\s*v(\d+(?:\.\d+)+)", readme))
        if vt and claimed and claimed != {vt[-1].lstrip("v")}:
            fails.append(f"README-VERSION {repo}: README says {sorted(claimed)}, newest release tag {vt[-1]}")
        for c in claims_from_text(f"{repo}/README.md", readme):
            if c["kind"] == "withheld" and c["line"] in live_lines:
                fails.append(f"WITHHELD-TEXT {repo}/README.md: {LINES[c['line']]} is live, README says {c['text']!r}")
            if c["kind"] == "price" and c["line"] in live_lines:
                price = ((snap.get("prices") or {}).get(c["line"]) or {}).get(f"{c['unit']}_usd")
                if price is not None and _num(str(price)) != c["value"]:
                    fails.append(f"PRICE {repo}/README.md: ${c['value']} vs live ${_num(str(price))}")
    for url in sources.get("pages") or []:
        raw = _get(url).decode("utf-8", "replace")
        read.append(url)
        for c in claims_from_text(urllib.parse.urlparse(url).path.lstrip("/"), page_text(raw)):
            if c["kind"] == "withheld" and c["line"] in live_lines:
                fails.append(f"WITHHELD-TEXT {url}: {LINES[c['line']]} is live, page says {c['text']!r}")
    return fails, read


def load_sources(path: Path) -> dict:
    """config/copy-truth-sources.yml: a small YAML subset (two lists of strings), read without PyYAML."""
    out: dict[str, list[str]] = {}
    key = None
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.split("#", 1)[0].rstrip()
        if not s:
            continue
        m = re.match(r"^([a-z_]+):\s*$", s)
        if m:
            key = m.group(1)
            out[key] = []
            continue
        m = re.match(r"^\s+-\s+(\S+)$", s)
        if m and key:
            out[key].append(m.group(1))
    return out


ISSUE_TITLE = "copy drift: public copy differs from production"
LABEL = "copy-drift"


def _findings(text: str) -> list[str]:
    return sorted(line for line in (text or "").splitlines() if line.startswith("- ") and " " in line[2:])


def sync_issue(report: str, drift: bool, token: str) -> str:
    """One issue, found by its exact title among open issues (not by label, which can be removed), labelled
    copy-drift (the label is created if missing). A comment is added only when the findings change."""
    api = f"https://api.github.com/repos/{REPO}"

    def call(method, url, body=None, ok404=False):
        req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body else None,
                                     headers={"Authorization": f"Bearer {token}", "User-Agent": "stigready-copy-drift/1",
                                              "Accept": "application/vnd.github+json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read() or b"null")
        except urllib.error.HTTPError as exc:
            if ok404 and exc.code == 404:
                return None
            raise CannotCheck(f"GitHub {method} {url}: HTTP {exc.code}") from exc

    if call("GET", f"{api}/labels/{LABEL}", ok404=True) is None:
        call("POST", f"{api}/labels", {"name": LABEL, "color": "d93f0b",
                                       "description": "Public copy differs from live AWS Marketplace (decision 0114)"})
    found = []
    for page in range(1, 6):
        batch = call("GET", f"{api}/issues?state=open&per_page=100&page={page}") or []
        found += [i for i in batch if i.get("title") == ISSUE_TITLE and "pull_request" not in i]
        if len(batch) < 100:
            break
    found.sort(key=lambda i: i["number"])
    if drift and not found:
        i = call("POST", f"{api}/issues", {"title": ISSUE_TITLE, "body": report, "labels": [LABEL]})
        return f"opened {i['html_url']}"
    if drift:
        issue = found[0]
        changed = _findings(issue.get("body")) != _findings(report)
        call("PATCH", f"{api}/issues/{issue['number']}", {"body": report, "labels": [LABEL]})
        if changed:
            call("POST", f"{api}/issues/{issue['number']}/comments", {"body": "The findings changed; the issue body "
                                                                         "now shows the latest run."})
        for dup in found[1:]:
            call("PATCH", f"{api}/issues/{dup['number']}", {"state": "closed"})
        return f"updated {issue['html_url']}" + (" (findings changed)" if changed else " (no change)")
    for i in found:
        call("POST", f"{api}/issues/{i['number']}/comments", {"body": "The drift has cleared: the site and the "
                                                                "READMEs match live AWS Marketplace again."})
        call("PATCH", f"{api}/issues/{i['number']}", {"state": "closed"})
    return f"closed {len(found)} issue(s)" if found else "no issue to update"


# ------------------------------------------------------------------------------------------------------------- main

def _report(title: str, fails: list[str], warns: list[str], extra: list[str]) -> str:
    out = [f"## {title}", ""] + extra + [""]
    out += [f"**{len(fails)} finding(s)**", ""] + [f"- {f}" for f in fails]
    if warns:
        out += ["", f"**{len(warns)} warning(s)**", ""] + [f"- {w}" for w in warns]
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["pr", "drift", "trust-root"], required=True)
    ap.add_argument("--site", type=Path, default=Path("."), help="pr: the site checkout to check (the PR head)")
    ap.add_argument("--repo", type=Path, default=Path("."), help="trust-root: the tree to check")
    ap.add_argument("--snapshot", type=Path, help="pr/drift: marketplace-live.json")
    ap.add_argument("--snapshot-sig", type=Path, help="pr/drift: its signature (default: <snapshot>.sig)")
    ap.add_argument("--snapshot-signers", type=Path, default=DEFAULT_SNAPSHOT_SIGNERS,
                    help=f"pr/drift: the snapshot keys (default: {SNAPSHOT_SIGNERS_PATH} of this checker's tree)")
    ap.add_argument("--max-age-hours", type=float, default=26.0)
    ap.add_argument("--now", help="ISO time to judge snapshot age by (fixtures)")
    ap.add_argument("--node", default=os.environ.get("COPY_TRUTH_NODE") or "node", help="the Node binary")
    ap.add_argument("--renderer", type=Path, default=RENDERER)
    ap.add_argument("--site-url", default="https://stigready.com")
    ap.add_argument("--sources", type=Path, default=Path("config/copy-truth-sources.yml"))
    ap.add_argument("--out", type=Path, help="write the Markdown report here")
    ap.add_argument("--issue", action="store_true", help="drift: open/update/close the copy-drift issue (GH_TOKEN)")
    ap.add_argument("--write", action="store_true", help=f"trust-root: rewrite {TRUST_ROOT_MANIFEST}")
    ap.add_argument("--base", type=Path, help="trust-root: take the entry list and the manifest from this tree (the "
                                              "base), and only the contents from --repo")
    a = ap.parse_args(argv)
    now = dt.datetime.fromisoformat(a.now.replace("Z", "+00:00")) if a.now else dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=dt.timezone.utc)

    def emit(text: str) -> None:
        print(text)
        if a.out:
            a.out.parent.mkdir(parents=True, exist_ok=True)
            a.out.write_text(text)

    try:
        if a.mode == "trust-root":
            ref = a.base or a.repo
            have = trust_root_of_dir(a.repo, ref)
            links = [f"refused trust root: {k} is a symlink" for k, v in sorted(have.items()) if v == SYMLINK]
            if a.write:
                if links:
                    raise CannotCheck("; ".join(links))
                (a.repo / TRUST_ROOT_MANIFEST).write_text(trust_root_render(have))
                print(f"wrote {TRUST_ROOT_MANIFEST}: {len(have)} entries")
                return 0
            want = trust_root_manifest(ref)
            diff = links + [f"changed trust root: {k} ({want.get(k, 'not in the manifest')} -> {have.get(k, 'gone')})"
                            for k in sorted(set(have) | set(want)) if have.get(k) != want.get(k) and have.get(k) != SYMLINK]
            where = (f"the list and manifest of {a.base} (the base)" if a.base else f"{TRUST_ROOT_MANIFEST} in this tree")
            emit(_report("copy-truth trust root (decision 0114)", diff, [],
                         [f"Compared against {where}. Each line is a change to what judges pull requests; "
                          "review/security reviews it." if diff else f"The trust root matches {where}."]))
            return 1 if diff else 0

        if a.mode == "pr":
            if not a.snapshot:
                raise CannotCheck("--snapshot is required: production state unknown")
            snap = load_snapshot(a.snapshot, now, a.max_age_hours, a.snapshot_sig, a.snapshot_signers)
            fails, warns = check_pr(load_site(a.site, a.node, a.renderer), snap)
            n = sum(1 for p in snap["products"] if p.get("visibility") == "Public")
            emit(_report("copy-truth (decision 0114 L1)", fails, warns,
                         [f"Snapshot generated {snap['generated']}, {n} live Public listings."]))
            return 1 if fails else 0

        # drift
        if not a.snapshot:
            raise CannotCheck("--snapshot is required: production state unknown")
        snap = load_snapshot(a.snapshot, now, a.max_age_hours, a.snapshot_sig, a.snapshot_signers)
        if not a.sources.is_file() or a.sources.is_symlink():
            raise CannotCheck(f"{a.sources} missing: the READMEs and pages it lists cannot be checked")
        sources = load_sources(a.sources)
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        with tempfile.TemporaryDirectory() as d:
            got = fetch_site(a.site_url, Path(d))
            fails, warns = check_pr(load_site(Path(d), a.node, a.renderer), snap)
        rf, read = check_readmes(sources, snap, token)
        fails += rf
        lead = ("The site or a public README describes a product differently from its live AWS Marketplace listing. "
                "Each line below names the page and what differs." if fails else
                "The site and the public READMEs match live AWS Marketplace.")
        report = _report(ISSUE_TITLE, fails, warns,
                         [lead, "",
                          f"Checked {now:%Y-%m-%d %H:%M} UTC against the Marketplace snapshot of {snap['generated']}: "
                          f"{len(got)} pages of {a.site_url} and {len(read)} READMEs and pages."])
        emit(report)
        if a.issue:
            if not token:
                raise CannotCheck("--issue needs GH_TOKEN (issues: write on stigready/stigready-web)")
            print(sync_issue(report, bool(fails), token))
        return 1 if fails else 0
    except CannotCheck as exc:
        emit(f"## cannot check\n\n{exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
