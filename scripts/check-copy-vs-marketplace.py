#!/usr/bin/env python3
"""Public copy must match production (claude-agents decision 0114).

Modes:

  --mode pr       (L1) The site in --site against the live Marketplace snapshot (--snapshot). Fails when a live-Public
                  product is shown as coming soon or missing, a product is shown as purchasable but is not live
                  Public, a line is called "coming soon" while it has live-Public listings, a price differs from the
                  live price, a region is claimed that no live listing of that line has, or a row's version or name
                  differs from its live listing. A missing, unparseable or stale snapshot fails (fail closed).
  --mode removal  (L2) --base-site against --site. Fails when a product moves down (purchasable > neutral > withheld),
                  disappears, or loses a price or region claim, or config/owner-signers changes, unless the PR carries
                  an owner approval approvals/owner/<digest>.{txt,sig} signed with a FIDO2 SSH key listed in --signers
                  (the base branch's config/owner-signers).
  --mode drift    (L3) Fetches the live site (--site-url, every page of its sitemap and /catalog.json), the public role
                  READMEs and the stigvalidated pages (config/copy-truth-sources.yml), checks them against the
                  snapshot (and each role README's release against its newest v* tag), writes a Markdown report and,
                  with --issue, opens, updates or closes the one `copy-drift` issue.

Exit 0: no finding. 1: findings. 2: cannot check (bad input, stale snapshot, fetch failure): never a pass.

The snapshot (schema stigready-marketplace-live/1) is written by stigready's `marketplace-live-snapshot` Cairn job
(granted marketplace-ro) to this repo's `live/marketplace` branch. Pull request runs get no credentials, so they read
that file instead of Marketplace; the Cairn job runs this script and the snapshot from the base branch, never the PR's.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import html
import html.parser
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

SCHEMA = "stigready-marketplace-live/1"
NAMESPACE = "stigready-owner-approval"
SIGNER_ID = "owner@stigready"
SK_TYPES = ("sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")
MAX_APPROVAL_DAYS = 14
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
STATE_RANK = {"purchasable": 2, "neutral": 1, "withheld": 0}


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


def load_site(root: Path) -> dict:
    """What the site shows: each catalog row's rendered state, and the claims in every page's text."""
    cat_path = root / "catalog.json"
    try:
        catalog = json.loads(cat_path.read_text(encoding="utf-8"))
        products = catalog["products"]
        assert isinstance(products, list)
    except (OSError, ValueError, KeyError, AssertionError) as exc:
        raise CannotCheck(f"{cat_path}: unreadable catalog ({type(exc).__name__})") from exc
    pages = {}
    for f in sorted(root.rglob("*.html")):
        rel = f.relative_to(root).as_posix()
        if rel.startswith(("approvals/", "cinc/", "scripts/", "assets/")) or any(
                part.startswith(".") for part in f.relative_to(root).parts):
            continue
        pages[rel] = f.read_text(encoding="utf-8", errors="replace")
    raw_all = "\n".join(pages.values())
    # How a row renders (index.html's availabilityCell, claude-agents#154): a linked listing only for an `available`
    # row with an AWS Marketplace pp/ URL, "Coming soon" for every other row. Pages that do not render availability at
    # all (before stigready-web#70) make no claim either way: neutral.
    renders_availability = "availabilityCell" in raw_all and "Coming soon" in raw_all
    renders_links = "marketplace_url" in raw_all
    claims = []
    for rel, raw in pages.items():
        claims += claims_from_text(rel, page_text(raw))
    withheld_lines = {c["line"] for c in claims if c["kind"] == "withheld"}
    rows = {}
    for p in products:
        url = p.get("marketplace_url")
        linked = (renders_links and p.get("availability") == "available" and isinstance(url, str)
                  and url.startswith(PP_PREFIX))
        if linked:
            row = "purchasable"
        elif renders_availability:
            row = "withheld"
        else:
            row = "neutral"
        shown = row
        if p.get("line") in withheld_lines and STATE_RANK[row] > STATE_RANK["withheld"] and row != "purchasable":
            shown = "withheld"
        rows[ident(p)] = {"row": row, "shown": shown, "product": p}
    return {"rows": rows, "claims": claims, "renders_availability": renders_availability}


# ------------------------------------------------------------------------------------------------------------ snapshot

def load_snapshot(path: Path, now: dt.datetime, max_age_hours: float) -> dict:
    try:
        snap = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
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
        if r is None:
            fails.append(f"MISSING {ident_str(k)}: live Public ({lp.get('product_id')}) but not on the site")
            continue
        if r["shown"] == "withheld":
            fails.append(f"WITHHELD {ident_str(k)}: live Public ({lp.get('product_id')}) but shown as coming soon")
        p = r["product"]
        versions = [str(v).lstrip("v") for v in lp.get("versions") or []]
        if versions and p.get("version") and str(p["version"]).lstrip("v") not in versions:
            fails.append(f"VERSION {ident_str(k)}: site {p['version']}, live listing {lp.get('product_id')} has "
                         f"{', '.join(lp.get('versions'))}")
        if lp.get("title"):
            why = name_mismatch(p, lp["title"])
            if why:
                fails.append(f"NAME {ident_str(k)}: site {p.get('os')!r}; {why}")
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


# --------------------------------------------------------------------------------------------------------------- L2

def downgrades(base: dict, head: dict, base_signers: str, head_signers: str) -> list[str]:
    out = []
    for k, b in base["rows"].items():
        h = head["rows"].get(k)
        if h is None:
            out.append(f"removed {ident_str(k)} (was {b['shown']})")
        elif STATE_RANK[h["shown"]] < STATE_RANK[b["shown"]]:
            out.append(f"downgraded {ident_str(k)} {b['shown']} -> {h['shown']}")
    for kind, field in (("price", "unit"), ("region", "region")):
        had = {(c["line"], c[field]) for c in base["claims"] if c["kind"] == kind and c["line"]}
        has = {(c["line"], c[field]) for c in head["claims"] if c["kind"] == kind and c["line"]}
        for ln, what in sorted(had - has):
            out.append(f"removed {kind} claim {LINES.get(ln, ln)} {what}")
    if base_signers != head_signers:
        out.append("changed config/owner-signers")
    return sorted(out)


def approval_message(items: list[str], expires: str) -> tuple[str, str]:
    digest = hashlib.sha256("\n".join(items).encode()).hexdigest()
    msg = (f"{NAMESPACE} v1\nrepo: {REPO}\ndigest: {digest}\nexpires: {expires}\n"
           + "".join(f"- {i}\n" for i in items))
    return digest, msg


def sk_signers(text: str, allow_software_key: bool) -> str:
    """Only FIDO2 keys (a signature needs a physical touch). --test-allow-software-key exists for the CINC fixtures;
    CINC control web-copy-truth-03 fails if the pipeline ever passes it."""
    keep = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if any(f" {t} " in f" {s} " for t in SK_TYPES) or (allow_software_key and " ssh-ed25519 " in f" {s} "):
            keep.append(s)
    return "\n".join(keep) + ("\n" if keep else "")


def verify_approval(head_root: Path, items: list[str], signers: str, today: dt.date,
                    allow_software_key: bool) -> tuple[bool, str]:
    digest = hashlib.sha256("\n".join(items).encode()).hexdigest()
    txt = head_root / "approvals" / "owner" / f"{digest}.txt"
    sig = head_root / "approvals" / "owner" / f"{digest}.sig"
    if not (txt.is_file() and sig.is_file()):
        return False, f"no owner approval: approvals/owner/{digest}.txt and .sig are not in the PR"
    body = txt.read_text(encoding="utf-8")
    m = re.search(r"^expires: (\d{4}-\d{2}-\d{2})$", body, re.M)
    if not m:
        return False, f"approvals/owner/{digest}.txt has no expires: line"
    expires = dt.date.fromisoformat(m.group(1))
    if expires < today or (expires - today).days > MAX_APPROVAL_DAYS:
        return False, f"approval expires {expires}: must be between today and {MAX_APPROVAL_DAYS} days out"
    _, want = approval_message(items, m.group(1))
    if body != want:
        return False, f"approvals/owner/{digest}.txt is not the canonical message for this change"
    allowed = sk_signers(signers, allow_software_key)
    if not allowed:
        return False, "config/owner-signers on the base branch lists no FIDO2 (sk-) key"
    with tempfile.TemporaryDirectory() as d:
        af = Path(d) / "allowed_signers"
        af.write_text(allowed)
        p = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(af), "-I", SIGNER_ID, "-n", NAMESPACE,
                            "-s", str(sig)], input=body.encode(), capture_output=True, timeout=30)
    if p.returncode != 0:
        return False, f"owner signature does not verify: {p.stderr.decode(errors='replace').strip()[:200]}"
    return True, f"owner approval {digest[:12]} verifies, expires {expires}"


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
        dest.write_bytes(_get(u))
        got.append(u)
    (into / "catalog.json").write_bytes(_get(site_url.rstrip("/") + "/catalog.json"))
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


def sync_issue(report: str, drift: bool, token: str) -> str:
    api = f"https://api.github.com/repos/{REPO}"

    def call(method, url, body=None):
        req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body else None,
                                     headers={"Authorization": f"Bearer {token}", "User-Agent": "stigready-copy-drift/1",
                                              "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read() or b"null")

    found = call("GET", f"{api}/issues?state=open&labels=copy-drift&per_page=10") or []
    found = [i for i in found if i.get("title") == ISSUE_TITLE and "pull_request" not in i]
    if drift and not found:
        i = call("POST", f"{api}/issues", {"title": ISSUE_TITLE, "body": report, "labels": ["copy-drift"]})
        return f"opened {i['html_url']}"
    if drift:
        call("PATCH", f"{api}/issues/{found[0]['number']}", {"body": report})
        call("POST", f"{api}/issues/{found[0]['number']}/comments", {"body": "Drift still present; body updated."})
        return f"updated {found[0]['html_url']}"
    for i in found:
        call("POST", f"{api}/issues/{i['number']}/comments", {"body": "Drift cleared:\n\n" + report})
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
    ap.add_argument("--mode", choices=["pr", "removal", "drift", "approval-message"], required=True)
    ap.add_argument("--site", type=Path, default=Path("."), help="the site checkout to check (the PR head)")
    ap.add_argument("--base-site", type=Path, help="removal: the base branch's site")
    ap.add_argument("--snapshot", type=Path, help="pr/drift: marketplace-live.json")
    ap.add_argument("--max-age-hours", type=float, default=26.0)
    ap.add_argument("--now", help="ISO time to judge snapshot age by (fixtures)")
    ap.add_argument("--signers", type=Path, help="removal: the BASE branch's config/owner-signers")
    ap.add_argument("--head-signers", type=Path, help="removal: the PR's config/owner-signers")
    ap.add_argument("--expires", help="approval-message: YYYY-MM-DD")
    ap.add_argument("--test-allow-software-key", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--site-url", default="https://stigready.com")
    ap.add_argument("--sources", type=Path, default=Path("config/copy-truth-sources.yml"))
    ap.add_argument("--out", type=Path, help="write the Markdown report here")
    ap.add_argument("--issue", action="store_true", help="drift: open/update/close the copy-drift issue (GH_TOKEN)")
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
        if a.mode == "pr":
            if not a.snapshot:
                raise CannotCheck("--snapshot is required: production state unknown")
            snap = load_snapshot(a.snapshot, now, a.max_age_hours)
            fails, warns = check_pr(load_site(a.site), snap)
            emit(_report("copy-truth (decision 0114 L1)", fails, warns,
                         [f"Snapshot generated {snap['generated']}, {sum(1 for p in snap['products'] if p.get('visibility') == 'Public')} live Public listings."]))
            return 1 if fails else 0

        if a.mode in ("removal", "approval-message"):
            if not a.base_site:
                raise CannotCheck("--base-site is required")
            bs = a.signers.read_text() if a.signers and a.signers.is_file() else ""
            hs = a.head_signers.read_text() if a.head_signers and a.head_signers.is_file() else bs
            items = downgrades(load_site(a.base_site), load_site(a.site), bs, hs)
            if a.mode == "approval-message":
                if not items:
                    print("nothing to approve: no product, price or region is withdrawn", file=sys.stderr)
                    return 1
                digest, msg = approval_message(items, a.expires or (now.date() + dt.timedelta(days=7)).isoformat())
                sys.stdout.write(msg)
                print(f"\nsign: ssh-keygen -Y sign -f <your sk key> -n {NAMESPACE} < approvals/owner/{digest}.txt "
                      f"# writes approvals/owner/{digest}.txt.sig: rename it to {digest}.sig", file=sys.stderr)
                return 0
            if not items:
                emit(_report("copy-removal-gate (decision 0114 L2)", [], [], ["No product, price or region is withdrawn."]))
                return 0
            # Bootstrap: while the base lists no FIDO2 key, the PR that adds the first one is verified with that key.
            signers = bs if sk_signers(bs, a.test_allow_software_key) else hs
            ok, why = verify_approval(a.site, items, signers, now.date(), a.test_allow_software_key)
            emit(_report("copy-removal-gate (decision 0114 L2)", [] if ok else items, [],
                         [why, "", "Generate the message to sign with `--mode approval-message`."]))
            return 0 if ok else 1

        # drift
        if not a.snapshot:
            raise CannotCheck("--snapshot is required: production state unknown")
        snap = load_snapshot(a.snapshot, now, a.max_age_hours)
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        with tempfile.TemporaryDirectory() as d:
            got = fetch_site(a.site_url, Path(d))
            fails, warns = check_pr(load_site(Path(d)), snap)
        sources = load_sources(a.sources) if a.sources.is_file() else {}
        rf, read = check_readmes(sources, snap, token)
        fails += rf
        report = _report(ISSUE_TITLE, fails, warns,
                         [f"Nightly read-only watch (decision 0114 L3), {now:%Y-%m-%d %H:%M} UTC.",
                          f"Snapshot generated {snap['generated']}.",
                          f"Read: {len(got)} pages of {a.site_url}, /catalog.json, {len(read)} READMEs/pages."])
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
