#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 StigReady
# SPDX-License-Identifier: LicenseRef-StigReady-Proprietary
"""Build the public evidence summary pages for StigReady Applied: one page per product and version, and an index.

Input: config/applied-evidence.json, written by scripts/extract-applied-evidence.py from the release store (never by
hand), and catalog.json. Output:

  applied/evidence/index.html                                every Applied version, its score and its page
  applied/evidence/<os_key>-<arch>-<profile>/v<version>/index.html
  applied/evidence/<os_key>-<arch>-<profile>/v<version>/sbom.cdx.json.gz   the bundle's CycloneDX SBOM, gzip -n

A page shows only what the bundle shows: the OpenSCAP score and counts, scan time, SSG profile and version, each
exemption with its reason and the customer action, refined values, CVE counts by severity with the scan date, the SBOM
and the signed manifest's digests. The full ARF and HTML reports, the per-CVE list and the build logs stay on request.

It refuses (exit 1, every reason printed) to build from a record that is not fit to publish: an extract problem, a
version or score that differs from catalog.json, an exemption class it has no public label for, a FIPS flag on a
non-STIG profile, a CVE scan where the scanner cannot assess the OS, or published text that names something internal.

    python3 scripts/build-evidence-pages.py           # write the pages
    python3 scripts/build-evidence-pages.py --check   # exit 1 if any page differs from what the input produces
    python3 scripts/build-evidence-pages.py --sbom-dir <extract out>/sbom   # also (re)write the SBOM downloads
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import html
import io
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "config" / "applied-evidence.json"
OUT = ROOT / "applied" / "evidence"
SITE = "https://stigready.com"

# Public wording for each exemption class in the build record. A class with no entry stops the build: a new class is
# a new public statement and is worded here, in review, not passed through.
CLASS_LABEL = {
    "aws-marketplace-conflict": "AWS Marketplace policy: you complete it after launch",
    "smartcard-cac": "Smart card / CAC: needs your PKI",
    "remote-log-offload": "Remote log offload: needs your log server",
    "derivative-os": "Check names Red Hat: cannot apply to this distribution",
    "owner-cloud-usability": "Cloud usability: you configure it after launch",
}
PROFILE_NAME = {"cis-l1": "CIS Benchmark Level 1", "cis-l2": "CIS Benchmark Level 2"}
# The STIG name depends on the OS (marketing review of stigready-web#99, C1): DISA publishes STIGs for RHEL 8/9 and
# Ubuntu 24.04; Rocky and AlmaLinux are scored with the RHEL STIG content; the RHEL 10 content is SSG's RHEL 10 STIG
# profile. An os_key with no entry stops the build.
STIG_NAME = {
    "rhel-8": "DISA STIG", "rhel-9": "DISA STIG", "ubuntu-24.04": "DISA STIG",
    "rocky-8": "with DISA RHEL 8 STIG", "alma-8": "with DISA RHEL 8 STIG",
    "rocky-9": "with DISA RHEL 9 STIG", "alma-9": "with DISA RHEL 9 STIG",
    "rhel-10": "STIG", "rocky-10": "with RHEL 10 STIG",
}
OS_LONG = {"rhel": "Red Hat Enterprise Linux", "rocky": "Rocky Linux", "alma": "AlmaLinux", "ubuntu": "Ubuntu"}
# Trivy does not assess the OS packages of these releases (stigready security policy, decision 0176): it detects the
# packages and matches no advisory, so its OS count is withheld. Language packages (Go binaries) are still counted.
OS_NOT_ASSESSED = ("rhel-10", "rocky-10", "alma-10")
# Releases where an OS-package count of zero has been reviewed and is published. Rocky Linux and AlmaLinux advisories
# list only fixed CVEs, so a patched image reads zero. Anywhere else a zero stops the build (fail closed): it is more
# likely a scanner that cannot see the OS than an image with no known CVEs.
OS_ZERO_REVIEWED = ("rocky-8", "rocky-9", "alma-8", "alma-9")
FIXED_ONLY_FAMILIES = ("rocky", "alma")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
LISTING_PREFIX = "https://aws.amazon.com/marketplace/"
SEVERITIES = ("critical", "high", "medium", "low", "unknown")
# Published text must not carry these (internal records, hosts, paths). Mirrors the published-paths control.
INTERNAL = re.compile(
    r"stigready/(?:stigforge|claude-agents|stigready|stigvalidated|cairn|build-reports)(?![\w-])"
    r"|\b(?:stigforge|stigready|stigvalidated|claude-agents|cairn)#\d+|\b[Dd]ecision\s+0\d{3}\b"
    r"|\b[Oo]wner(?:\s+decision|\s+direction|,?\s*20\d\d-\d\d-\d\d)|\.consul\b|/mnt/|\bqemu-\d|192\.168\."
    r"|\bami-[0-9a-f]{8,}\b|GovCloud|FedRAMP|\bATO\b|FIPS[ -]validated|FIPS 140-[23] validated|co-sell|\bFTR\b", re.I)

NON_AFFILIATION = ("Not affiliated with or endorsed by DISA, DoD, NIST, CIS, Red Hat, Canonical, Amazon, the Rocky "
                   "Enterprise Software Foundation, or the AlmaLinux OS Foundation.")
TRADEMARKS = (
    "All trademarks are the property of their respective owners. Red Hat®, Red Hat Enterprise Linux® and Ansible® are "
    "trademarks of Red Hat, Inc. Ubuntu® is a trademark of Canonical Ltd. Amazon Web Services, AWS, AWS Marketplace, "
    "Graviton and Amazon Linux are trademarks of Amazon.com, Inc. or its affiliates. Rocky Linux is a trademark of the "
    "Rocky Enterprise Software Foundation. AlmaLinux is a trademark of the AlmaLinux OS Foundation. Linux is the "
    "registered trademark of Linus Torvalds in the U.S. and other countries. CIS® and CIS Benchmarks™ are trademarks "
    "of the Center for Internet Security, Inc. StigReady does not provide commercial licenses for Red Hat products.")
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; object-src 'none'; "
       "base-uri 'self'; form-action 'self'")
STYLE = """
        body { font-family: 'Inter', sans-serif; }
        .gold { color: #C9A84C; }
        .bg-navy { background-color: #0C2340; }
        .ev { max-width: 64rem; margin: 0 auto; padding: 3rem 1rem; }
        .ev h1 { font-size: 1.9rem; font-weight: 900; color: #fff; line-height: 1.2; margin: 0 0 .5rem; }
        .ev h2 { font-size: 1.25rem; font-weight: 700; color: #fff; margin: 2.5rem 0 .75rem; }
        .ev p, .ev li { color: #d1d5db; font-size: .95rem; line-height: 1.6; }
        .ev p { margin: 0 0 .75rem; }
        .ev .muted { color: #9ca3af; font-size: .85rem; }
        .ev a { color: #eab308; }
        .ev a:hover { text-decoration: underline; }
        .ev code { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: .85em; color: #e5e7eb; word-break: break-all; }
        .ev .tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr)); gap: .75rem; margin: 1.5rem 0; }
        .ev .tile { background: #1f2937; border: 1px solid #374151; border-radius: .5rem; padding: .9rem 1rem; }
        .ev .tile .k { color: #9ca3af; font-size: .75rem; text-transform: uppercase; letter-spacing: .05em; }
        .ev .tile .v { color: #fff; font-size: 1.5rem; font-weight: 700; }
        .ev .tbl { overflow-x: auto; border: 1px solid #374151; border-radius: .5rem; }
        .ev table { width: 100%; border-collapse: collapse; font-size: .85rem; }
        .ev th { text-align: left; color: #9ca3af; font-weight: 600; background: #111827; padding: .55rem .7rem; border-bottom: 1px solid #374151; }
        .ev td { color: #d1d5db; padding: .55rem .7rem; border-bottom: 1px solid #1f2937; vertical-align: top; }
        .ev h3 { font-size: 1rem; font-weight: 600; color: #fff; margin: 1.25rem 0 .5rem; }
        .ev ul { list-style: disc; padding-left: 1.25rem; margin: 0 0 .75rem; }
    """

problems: list[str] = []


def e(s) -> str:
    return html.escape("" if s is None else str(s), quote=True)


def prose(s) -> str:
    """Escape record text, then show its `code` spans as code (the build record writes commands in backticks)."""
    return re.sub(r"`([^`<>]+)`", r"<code>\1</code>", e(s))


def utc(ts: str | None) -> str:
    """ISO timestamp (any offset, nanoseconds allowed) -> 'YYYY-MM-DD HH:MM UTC'."""
    if not ts:
        return "unknown"
    m = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?(Z|[+-]\d\d:\d\d)?$", ts)
    if not m:
        return e(ts)
    off = m.group(2) or "+00:00"
    dt = datetime.fromisoformat(m.group(1) + ("+00:00" if off == "Z" else off)).astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def os_long(os_key: str) -> str:
    fam, _, ver = os_key.partition("-")
    return f"{OS_LONG.get(fam, fam)} {ver}"


def profile_label(c: dict) -> str:
    if c["profile"] == "stig":
        return STIG_NAME[c["os_key"]]
    return PROFILE_NAME[c["profile"]]


def image_label(c: dict) -> str:
    """'RHEL 9 DISA STIG', 'Rocky Linux 9 with DISA RHEL 9 STIG', 'RHEL 10 STIG', 'Ubuntu 24.04 CIS Benchmark Level 1'."""
    return f"{c['os']} {profile_label(c)}"


def product_name(c: dict) -> str:
    return f"StigReady Applied {image_label(c)} ({c['arch']})"


def page_rel(c: dict) -> str:
    return f"applied/evidence/{c['cell']}/v{c['version']}/"


def product_rel(c: dict) -> str:
    """The product's stable page: what its AWS Marketplace listing links, whatever version it sells."""
    return f"applied/evidence/{c['cell']}/"


def accounts(regex: str | None) -> list[str] | None:
    m = re.fullmatch(r"\^\(([\w|.-]+)\)\$", regex or "")
    return m.group(1).split("|") if m else None


def head(title: str, desc: str, canonical: str) -> str:
    return f"""<!DOCTYPE html>
<!-- SPDX-FileCopyrightText: 2026 StigReady -->
<!-- SPDX-License-Identifier: LicenseRef-StigReady-Proprietary -->
<!-- Generated by scripts/build-evidence-pages.py from config/applied-evidence.json. Change the generator or its input, not this file. -->
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Security-Policy" content="{CSP}">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{e(title)}</title>
    <meta name="description" content="{e(desc)}">
    <meta name="author" content="StigReady">
    <meta name="robots" content="index,follow">
    <meta name="theme-color" content="#0C2340">
    <link rel="canonical" href="{SITE}/{canonical}">
    <link rel="icon" type="image/png" href="https://stigready.com/assets/logo.png">
    <link rel="stylesheet" href="/assets/css/site.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;900&display=swap" rel="stylesheet">
    <style>{STYLE}</style>
</head>
<body class="bg-gray-900 text-gray-100 min-h-screen flex flex-col">
    <nav class="bg-navy border-b border-gray-800 px-6 py-4 sticky top-0 z-20">
        <div class="max-w-6xl mx-auto flex items-center justify-between">
            <a href="/" class="flex items-center space-x-3" aria-label="StigReady home">
                <img src="/assets/logo.png" alt="StigReady" class="h-10 w-auto" width="40" height="40"/>
                <span class="text-xl font-black tracking-wide"><span class="text-white">STIG</span><span class="gold">READY</span></span>
            </a>
            <div class="hidden md:flex items-center space-x-6 text-sm font-medium">
                <a href="/#base-tier" class="text-gray-300 hover:text-white transition">Base</a>
                <a href="/applied/" class="text-white">Applied</a>
                <a href="/applied/evidence/" class="text-gray-300 hover:text-white transition">Evidence</a>
                <a href="/blog/" class="text-gray-300 hover:text-white transition">Blog</a>
                <a href="mailto:contact@stigready.com" class="bg-yellow-600 hover:bg-yellow-500 text-white px-4 py-2 rounded-md font-semibold transition">Contact</a>
            </div>
        </div>
    </nav>
    <main class="flex-1">
    <div class="ev">
"""


def foot() -> str:
    return f"""    </div>
    </main>

    <footer class="bg-navy py-8 px-4 border-t border-gray-800">
        <p class="text-center text-xs text-gray-500 mb-3"><a href="/data-practices/" class="hover:text-white transition">Data practices</a></p>
        <p class="text-center text-xs text-gray-600">&copy; 2026 StigReady. All rights reserved.</p>
        <p class="text-center text-xs text-gray-600 mt-3 max-w-3xl mx-auto">
            {e(NON_AFFILIATION)} {e(TRADEMARKS)}
        </p>
    </footer>
</body>
</html>
"""


def is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def os_counts(c: dict) -> dict | None:
    return ((c.get("cve") or {}).get("classes") or {}).get("os-pkgs")


def check_types(c: dict, where: str) -> bool:
    """Every number a page prints must be a number of the right kind (security review S3)."""
    bad = []
    sc = c.get("scorecard") or {}
    if not (isinstance(sc.get("score"), (int, float)) and not isinstance(sc.get("score"), bool) and 0 <= sc["score"] <= 100):
        bad.append("scorecard.score")
    bad += [f"scorecard.{k}" for k in ("pass", "fail", "notapplicable", "notchecked") if not is_int(sc.get(k))]
    for cls, acc in (((c.get("cve") or {}).get("classes")) or {}).items():
        bad += [f"cve.{cls}.{k}" for k in ("packages", "findings") if not is_int(acc.get(k))]
        for field in ("distinct", "distinct_fixable"):
            d = acc.get(field) or {}
            bad += [f"cve.{cls}.{field}.{s}" for s in SEVERITIES if not is_int(d.get(s))]
    if not is_int((c.get("sbom") or {}).get("components")):
        bad.append("sbom.components")
    if not is_int((c.get("signature") or {}).get("manifest_files")):
        bad.append("signature.manifest_files")
    for b in bad:
        problems.append(f"{where}: {b} is not a number of the expected type")
    return not bad


def check_record(c: dict, cat: dict) -> None:
    where = f"{c.get('cell')} v{c.get('version')}"
    for p in c.get("problems") or []:
        problems.append(f"{where}: extract problem: {p}")
    if c.get("problems"):
        return
    if not VERSION_RE.match(str(c.get("version"))):
        problems.append(f"{where}: version is not N.N.N")
        return
    if c.get("cell") != f"{c.get('os_key')}-{c.get('arch')}-{c.get('profile')}":
        problems.append(f"{where}: cell is not <os_key>-<arch>-<profile>")
        return
    if not check_types(c, where):
        return
    row = cat.get((c["os_key"], c["arch"], c["profile"]))
    if row is None or row.get("line") != "stigapplied" or row.get("availability") != "available":
        problems.append(f"{where}: not an available Applied row in catalog.json")
        return
    if not str(row.get("marketplace_url") or "").startswith(LISTING_PREFIX):
        problems.append(f"{where}: catalog.json marketplace_url is not under {LISTING_PREFIX}")
    if row.get("version") != c["version"]:
        problems.append(f"{where}: catalog.json sells v{row.get('version')}")
    if row.get("score") != c["scorecard"]["score"]:
        problems.append(f"{where}: catalog.json score {row.get('score')} is not the signed score {c['scorecard']['score']}")
    sc = c["scorecard"]
    if sc["pass"] + sc["fail"] == 0 or round(100 * sc["pass"] / (sc["pass"] + sc["fail"]), 1) != sc["score"]:
        problems.append(f"{where}: score {sc['score']} is not pass/(pass+fail)")
    if c["fips"] != (c["profile"] == "stig"):
        problems.append(f"{where}: FIPS {c['fips']} on profile {c['profile']}")
    if c["profile"] == "stig" and c["os_key"] not in STIG_NAME:
        problems.append(f"{where}: no STIG name for {c['os_key']}")
    if not c.get("ami_matches_live_listing"):
        problems.append(f"{where}: the bundle was not matched to the live listing's AMI")
    if (c.get("signature") or {}).get("cosign_verified") is not True:
        problems.append(f"{where}: signature not verified at extraction")
    if len(c["exemptions"]) != sc["fail"] or c["gate"].get("nonexempt_failures") != 0:
        problems.append(f"{where}: {sc['fail']} failing rules but {len(c['exemptions'])} exemptions")
    for x in c["exemptions"]:
        if x["class"] not in CLASS_LABEL:
            problems.append(f"{where}: exemption class {x['class']!r} has no public label")
    osc = os_counts(c)
    if osc is None:
        problems.append(f"{where}: the CVE scan has no OS-package result")
    elif c["os_key"] not in OS_NOT_ASSESSED and osc["findings"] == 0 and c["os_key"] not in OS_ZERO_REVIEWED:
        # Fail closed: a zero here is more likely a scanner that cannot see the OS (as on EL 10) than a clean image.
        problems.append(f"{where}: zero OS-package findings on {c['os_key']}, which is neither OS_NOT_ASSESSED nor "
                        "OS_ZERO_REVIEWED; review whether Trivy can assess it")
    if (c["os_key"].split("-")[0] in ("rhel", "rocky", "alma") and int(c["os_key"].split("-")[1].split(".")[0]) >= 10
            and c["os_key"] not in OS_NOT_ASSESSED):
        problems.append(f"{where}: {c['os_key']} is an EL 10 release missing from OS_NOT_ASSESSED")
    if set((c["cve"]["classes"] or {})) - {"os-pkgs", "lang-pkgs"}:
        problems.append(f"{where}: a Trivy result class with no public wording: {sorted(c['cve']['classes'])}")
    filt = (c.get("cve") or {}).get("severity_filter")
    if not filt or not {x.lower() for x in filt} <= set(SEVERITIES):
        problems.append(f"{where}: the CVE scan's severity filter is not recorded")
    else:
        for cls, acc in c["cve"]["classes"].items():
            for sv in SEVERITIES:
                if sv not in {x.lower() for x in filt} and acc["distinct"][sv]:
                    problems.append(f"{where}: {cls} has {sv} findings outside the scan's severity filter {filt}")
    if not c.get("sbom"):
        problems.append(f"{where}: no SBOM")


def exemption_rows(c: dict) -> str:
    rows = []
    for x in c["exemptions"]:
        disa = ", ".join(x.get("disa") or []) or "no STIG ID in the build record"
        rows.append(
            f"<tr><td><code>{e(x['rule'])}</code><br><span class=\"muted\">{e(x['title'])}</span></td>"
            + (f"<td>{e(disa)}</td>" if c["profile"] == "stig" else "")
            + f"<td>{e(CLASS_LABEL[x['class']])}</td><td>{prose(x['why'])}</td><td>{prose(x['customer_action'])}</td></tr>")
    disa_h = "<th>STIG ID</th>" if c["profile"] == "stig" else ""
    return (f"<div class=\"tbl\"><table><thead><tr><th>Rule</th>{disa_h}<th>Category</th><th>Why it fails in the image"
            f"</th><th>What you do</th></tr></thead><tbody>\n" + "\n".join(rows) + "\n</tbody></table></div>")


SEV_TITLE = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "unknown": "Unrated"}


def scanned(c: dict) -> list[str]:
    """The severities the scan ran with, in table order (Trivy --severity, from the signed build log)."""
    f = {x.lower() for x in c["cve"]["severity_filter"]}
    return [s for s in SEVERITIES if s in f]


def count_table(acc: dict, sevs: list[str], found: str, fixed: str) -> str:
    head_ = "".join(f"<th>{SEV_TITLE[s]}</th>" for s in sevs)
    cells = "".join(f"<td>{e(acc['distinct'][s])}</td>" for s in sevs)
    fix = "".join(f"<td>{e(acc['distinct_fixable'][s])}</td>" for s in sevs)
    return (f"<div class=\"tbl\"><table><thead><tr><th></th>{head_}</tr></thead><tbody>\n<tr><td>{found}</td>{cells}"
            f"</tr>\n<tr><td>{fixed}</td>{fix}</tr>\n</tbody></table></div>\n")


def cve_section(c: dict) -> str:
    v = c["cve"]
    fam = c["os_key"].split("-")[0]
    osn = e(os_long(c["os_key"]))
    fixed_label = "Of those, Trivy reported a fixed package version at scan time"
    sevs = scanned(c)
    skipped = [SEV_TITLE[s] for s in SEVERITIES if s not in sevs]
    out = [f"<p>Scanned with Trivy {e(v['scanner_version'])} in the image build on {utc(v['created_at'])}, for "
           f"{e(', '.join(SEV_TITLE[s] for s in sevs))} severity only"
           + (f" ({e(' and '.join(skipped))} severity CVEs were not scanned for and are not counted)" if skipped else "")
           + ". Counts are distinct CVE identifiers at that date; CVEs published later are not counted. OS packages "
           "and language packages are counted separately.</p>\n<h3>OS packages</h3>\n"]
    osc = v["classes"]["os-pkgs"]
    if c["os_key"] in OS_NOT_ASSESSED:
        if osc["findings"] == 0:
            out.append(f"<p>Not assessed. Trivy detected the {osn} packages but its vulnerability data does not cover "
                       f"{osn}, so it matched none, and that zero would not mean the image has no known CVEs.</p>\n")
        else:
            out.append(f"<p>Not fully assessed. Trivy's vulnerability data for {osn} is incomplete. It matched the CVEs "
                       "below, so they are present, but the image may have others it could not see. Read these as a "
                       "lower bound.</p>\n" + count_table(osc, sevs, "CVEs found (at least)", fixed_label))
    else:
        out.append(count_table(osc, sevs, "CVEs found", fixed_label))
        if fam in FIXED_ONLY_FAMILIES:
            out.append(f"<p class=\"muted\">Trivy's data for Rocky Linux and AlmaLinux lists only CVEs that have a "
                       "published fix, so these counts do not include unfixed CVEs and are not comparable with the Red "
                       "Hat Enterprise Linux pages.</p>\n")
    lang = v["classes"].get("lang-pkgs")
    if lang:
        out.append("<h3>Language packages (Go binaries)</h3>\n"
                   f"<p>Go modules and the Go standard library compiled into binaries in the image, such as the AWS "
                   f"Systems Manager agent: {e(lang['packages'])} detected.</p>\n"
                   + count_table(lang, sevs, "CVEs found", fixed_label))
    out.append("<p class=\"muted\">The per-CVE list is in the full evidence bundle, on request.</p>")
    return "".join(out)


def version_page(c: dict, row: dict, extracted: str) -> str:
    sc, x, name = c["scorecard"], c["xccdf"], product_name(c)
    prof = c["ssg_profile"]
    fam = c["os_key"].split("-")[0]
    ver = c["version"]
    title = f"{name} v{ver} — build evidence summary"
    desc = (f"OpenSCAP score {sc['score']:.1f}% for {name} v{ver}: counts, exemptions with reasons, CVE counts, SBOM "
            "and signed digests.")
    body = [head(title, desc, page_rel(c))]
    body.append(f"""        <p class="text-xs text-yellow-500 font-semibold uppercase tracking-widest mb-3"><a href="/applied/evidence/">Applied evidence</a> / {e(c['cell'])}</p>
        <h1>{e(name)} <span class="gold">v{e(ver)}</span></h1>
        <p>Build evidence summary for version v{e(ver)} of this image, taken from that version's evidence bundle. The
        Signature section lists the signed files it was read from. A later version gets its own page.</p>
        <p><a href="{e(row['marketplace_url'])}" rel="noopener noreferrer">AWS Marketplace listing</a> ·
        <a href="/{product_rel(c)}">All versions of this image</a> · <a href="/applied/evidence/">All Applied images</a></p>
        <div class="tiles">
            <div class="tile"><div class="k">OpenSCAP score</div><div class="v">{sc['score']:.1f}%</div></div>
            <div class="tile"><div class="k">Rules passed</div><div class="v">{e(sc['pass'])}</div></div>
            <div class="tile"><div class="k">Rules failed</div><div class="v">{e(sc['fail'])}</div></div>
            <div class="tile"><div class="k">Not applicable</div><div class="v">{e(sc['notapplicable'])}</div></div>
            <div class="tile"><div class="k">Not checked</div><div class="v">{e(sc['notchecked'])}</div></div>
        </div>

        <h2>How it was scored</h2>
        <ul>
            <li>Scanned with OpenSCAP in the image build on {utc(x['start_time'])}.</li>
            <li>Content: SCAP Security Guide {e(x['ssg_version'])}, profile “{e(prof['title'])}”
                (<code>{e(prof['id'])}</code>){f", with the refined value{'s' if len(c['tailoring']) != 1 else ''} listed below" if prof['tailored'] else ", as published"}.</li>
            <li>Score = rules passed ÷ (rules passed + rules failed). Every rule listed under Exemptions failed in the
                scan and counts as a failure in the score. Not-applicable and not-checked rules are not scored.</li>
""")
    major = c["os_key"].split("-")[1]
    if c["profile"] == "stig" and fam in ("rocky", "alma"):
        body.append(f"""            <li>This image runs {e(OS_LONG[fam])} {e(major)}, not Red Hat Enterprise Linux. Red Hat does not
                provide, support or endorse it.</li>
""")
    if c["profile"] == "stig" and major == "10":
        body.append("""            <li>Scored with the SCAP Security Guide's RHEL 10 STIG profile.</li>
""")
    if fam in ("rocky", "alma"):
        body.append(f"""            <li>{e(OS_LONG[fam])} is scored with the SCAP Security Guide content for Red Hat Enterprise Linux, so
                the checks that only Red Hat Enterprise Linux can pass appear as exemptions below.</li>
""")
    if c["gate"].get("enforce") is True:
        body.append(f"""            <li>The build's OpenSCAP gate was enforced: floor {e(c['gate']['floor'])}%, and no failing rule without a
                documented exemption.</li>
""")
    if c["profile"] == "stig":
        body.append("""            <li>FIPS mode is enabled, using the OS vendor's FIPS cryptographic modules.</li>
""")
        if fam == "ubuntu":
            body.append("""            <li>No Ubuntu Pro subscription is included. Ongoing ESM and FIPS updates require your own Ubuntu Pro
                subscription.</li>
""")
    if fam == "ubuntu" and c["profile"] != "stig":
        body.append("""            <li>No Ubuntu Pro subscription is included. Security fixes published only through Ubuntu Pro (ESM)
                require your own Ubuntu Pro subscription.</li>
""")
    if fam == "rhel":
        body.append("""            <li>Red Hat Enterprise Linux images are BYOL: you supply your own Red Hat subscription. StigReady does
                not sell or provide Red Hat commercial licenses.</li>
""")
    body.append("""        </ul>
        <p class="muted">An OpenSCAP score measures this image against SSG content. It is not a certification,
        authorization or accreditation, and it is not an assessment of your system.</p>
""")

    n = len(c["exemptions"])
    src = ("the signed POA&amp;M lists the same rules" if c.get("poam_signed")
           else "this record is not covered by the bundle's signature")
    body.append(f"""
        <h2>Exemptions ({n})</h2>
        <p>Each rule below fails in the image for the reason given, and the last column is what you do to meet it
        on your instance. The reasons and actions come from the build record ({src}).</p>
        {exemption_rows(c) if n else '<p>None.</p>'}
""")
    if c["tailoring"]:
        body.append("""
        <h2>Refined values</h2>
        <p>The scan used the SSG profile with these values changed. The change is in the bundle's signed tailoring
        file.</p>
""")
        for t in c["tailoring"]:
            base, used = accounts(t.get("ssg_default")), accounts(t.get("value"))
            if base is not None and used is not None and set(base) <= set(used):
                added = [a for a in used if a not in base]
                what = (f"The SSG default list of local accounts, plus the accounts this image itself has: "
                        f"{', '.join(f'<code>{e(a)}</code>' for a in added)}.")
            else:
                what = f"SSG default: <code>{e(t.get('ssg_default'))}</code>."
            body.append(f"""        <p><code>{e(t['variable'])}</code>: {what}</p>
        <p class="muted">Value used: <code>{e(t['value'])}</code></p>
""")
    body.append(f"""
        <h2>CVE scan</h2>
        {cve_section(c)}

        <h2>SBOM</h2>
        <p>{e(c['sbom']['format'])}, {e(c['sbom']['components'])} components:
        <a href="sbom.cdx.json.gz">sbom.cdx.json.gz</a> (gzip). Uncompressed, its SHA-256 is the one in the signed
        manifest: <code>{e(c['sbom']['sha256'].removeprefix('sha256:'))}</code>.</p>

        <h2>Signature</h2>
        <p>The bundle's manifest lists a SHA-256 digest for each of its {e(c['signature']['manifest_files'])} files and was
        signed with cosign on {utc(c['signature']['signed_at'])}. When this summary was extracted on
        {e(extracted[:10])}, the signature verified and each file this page summarises matched its digest:</p>
        <div class="tbl"><table><thead><tr><th>File in the bundle</th><th>SHA-256</th></tr></thead><tbody>
""")
    for rel, dg in sorted(c["signed_digests"].items()):
        body.append(f"""        <tr><td><code>{e(rel)}</code></td><td><code>{e((dg or '').removeprefix('sha256:'))}</code></td></tr>
""")
    body.append("""        </tbody></table></div>

        <h2>The full bundle</h2>
        <p>The OpenSCAP ARF and HTML reports, the per-CVE list, the build logs and the rest of the bundle are
        available from <a href="mailto:support@stigready.com">support@stigready.com</a> on request.</p>
""")
    body.append(foot())
    return "".join(body)


def product_page(versions: list[dict], row: dict, meta: dict) -> str:
    c = versions[-1]
    name = product_name(c)
    out = [head(f"{name} — build evidence", f"Build evidence summaries for each version of {name}.", product_rel(c))]
    out.append(f"""        <p class="text-xs text-yellow-500 font-semibold uppercase tracking-widest mb-3"><a href="/applied/evidence/">Applied evidence</a> / {e(c['cell'])}</p>
        <h1>{e(name)}</h1>
        <p>Build evidence summaries for this image, one page per version. The version its
        <a href="{e(row['marketplace_url'])}" rel="noopener noreferrer">AWS Marketplace listing</a> offered on
        {e(meta['extracted_at'][:10])} was v{e(row['version'])}.</p>
        <div class="tbl"><table><thead><tr><th>Version</th><th>OpenSCAP score</th><th>Scanned</th><th>Evidence</th></tr></thead><tbody>
""")
    for v in sorted(versions, key=lambda v: [int(x) for x in v["version"].split(".")], reverse=True):
        out.append(f"""        <tr><td>v{e(v['version'])}</td><td>{v['scorecard']['score']:.1f}%</td><td>{utc(v['xccdf']['start_time'])}</td><td><a href="/{page_rel(v)}">Summary</a></td></tr>
""")
    out.append("""        </tbody></table></div>
""")
    out.append(foot())
    return "".join(out)


def index_page(cells: list[dict], cat: dict, meta: dict) -> str:
    title = "StigReady Applied — build evidence summaries"
    desc = ("Per-version evidence for every StigReady Applied image: OpenSCAP score and counts, exemptions with reasons, "
            "CVE counts, SBOM and signed digests.")
    out = [head(title, desc, "applied/evidence/")]
    out.append(f"""        <p class="text-xs text-yellow-500 font-semibold uppercase tracking-widest mb-3">StigReady Applied</p>
        <h1>Build evidence, <span class="gold">per version</span></h1>
        <p>Each StigReady Applied image version has a summary of its signed build evidence: the OpenSCAP score and rule
        counts, every exemption with its reason and what you do about it, the CVE counts by severity, the SBOM, and the
        digests from the bundle's signed manifest. The full bundle (ARF and HTML reports, per-CVE list, build logs) is
        available from <a href="mailto:support@stigready.com">support@stigready.com</a> on request.</p>
        <p class="muted">The versions below are the ones the AWS Marketplace listings offered on
        {e(meta['extracted_at'][:10])}. Each page describes one version only.</p>
        <div class="tbl"><table><thead><tr><th>Image</th><th>Architecture</th><th>Profile</th><th>Version</th>
        <th>OpenSCAP score</th><th>Scanned</th><th>Evidence</th></tr></thead><tbody>
""")
    for c in sorted(cells, key=lambda c: (c["os_key"], c["profile"], c["arch"])):
        out.append(f"""        <tr><td>{e(c['os'])}</td><td>{e(c['arch'])}</td><td>{e(profile_label(c))}</td><td>v{e(c['version'])}</td><td>{c['scorecard']['score']:.1f}%</td><td>{utc(c['xccdf']['start_time'])[:10]}</td><td><a href="/{page_rel(c)}">Summary</a> · <a href="/{product_rel(c)}">All versions</a></td></tr>
""")
    out.append("""        </tbody></table></div>
        <p class="muted mt-4">Scores measure each image against SCAP Security Guide content with OpenSCAP. They are not a
        certification, authorization or accreditation.</p>
""")
    out.append(foot())
    return "".join(out)


def rel(p: Path) -> str:
    try:
        return str(p.relative_to(ROOT))
    except ValueError:
        return str(p)


def gz(data: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, compresslevel=9, mtime=0) as f:
        f.write(data)
    return buf.getvalue()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="compare, write nothing")
    ap.add_argument("--input", type=Path, default=INPUT)
    ap.add_argument("--catalog", type=Path, default=ROOT / "catalog.json")
    ap.add_argument("--out", type=Path, default=OUT)
    ap.add_argument("--sitemap", type=Path, default=ROOT / "sitemap.xml")
    ap.add_argument("--sbom-dir", type=Path, help="the extract's sbom/ directory: write each SBOM download from it")
    a = ap.parse_args(argv)

    doc = json.loads(a.input.read_text(encoding="utf-8"))
    cat = {(p["os_key"], p["arch"], p["profile"]): p
           for p in json.loads(a.catalog.read_text(encoding="utf-8"))["products"] if p.get("line") == "stigapplied"}
    if not (doc.get("live_listings_checked") and doc.get("signatures_checked")):
        problems.append("the extract was made without the live-listing or signature check")
    cells = doc.get("cells") or []
    for c in cells:
        check_record(c, cat)
    have = {(c["os_key"], c["arch"], c["profile"]) for c in cells if "os_key" in c}
    for k, p in cat.items():
        if p.get("availability") == "available" and k not in have:
            problems.append(f"{':'.join(k)}: available in catalog.json but has no evidence record")

    pages: dict[Path, bytes] = {}
    if not problems:
        pages[a.out / "index.html"] = index_page(cells, cat, doc).encode()
        by_product: dict[str, list[dict]] = {}
        for c in cells:
            by_product.setdefault(c["cell"], []).append(c)
        for cell, versions in by_product.items():
            k = (versions[0]["os_key"], versions[0]["arch"], versions[0]["profile"])
            pages[a.out / cell / "index.html"] = product_page(versions, cat[k], doc).encode()
        for c in cells:
            d = a.out / c["cell"] / f"v{c['version']}"
            pages[d / "index.html"] = version_page(c, cat[(c["os_key"], c["arch"], c["profile"])], doc["extracted_at"]).encode()
            if c["profile"] != "stig" and b"FIPS" in pages[d / "index.html"]:
                problems.append(f"{c['cell']} v{c['version']}: a non-STIG page mentions FIPS")
        for p, body in pages.items():
            for n, line in enumerate(body.decode().splitlines(), 1):
                m = INTERNAL.search(line)
                if m:
                    problems.append(f"{rel(p)}:{n}: published text names {m.group(0)!r}")
    # Every SBOM download must be the signed SBOM: gunzip, then SHA-256 equals the manifest digest.
    for c in cells if not problems else []:
        d = a.out / c["cell"] / f"v{c['version']}"
        target = d / "sbom.cdx.json.gz"
        if a.sbom_dir:
            raw = (a.sbom_dir / f"{c['cell']}-v{c['version']}.cdx.json").read_bytes()
            pages[target] = gz(raw)
        if target in pages:
            raw = gzip.decompress(pages[target])
        elif target.is_file():
            raw = gzip.decompress(target.read_bytes())
        else:
            problems.append(f"{rel(target)}: missing")
            continue
        if "sha256:" + hashlib.sha256(raw).hexdigest() != c["sbom"]["sha256"]:
            problems.append(f"{rel(target)}: not the signed SBOM")

    if problems:
        print(f"build-evidence-pages: {len(problems)} problem(s), nothing written", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1

    expected = {p for p in pages if p.name == "index.html"}
    expected |= {a.out / c["cell"] / f"v{c['version']}" / "sbom.cdx.json.gz" for c in cells}
    existing = ({p for p in a.out.rglob("index.html")} | {p for p in a.out.rglob("*.gz")}) if a.out.is_dir() else set()
    # Every page is in sitemap.xml with the extraction date, and the sitemap names no evidence page that is gone.
    sitemap = a.sitemap.read_text(encoding="utf-8") if a.sitemap.is_file() else ""
    want = {f"{SITE}/{p.parent.relative_to(a.out.parent.parent).as_posix()}/" for p in expected if p.name == "index.html"}
    listed = set(re.findall(r"<loc>(https://stigready\.com/applied/evidence/[^<]*)</loc>", sitemap))
    if a.check:
        bad = [rel(p) for p in sorted(expected) if p in pages and (not p.is_file() or p.read_bytes() != pages[p])]
        bad += [f"{rel(p)} (stale: no record)" for p in sorted(existing - expected)]
        bad += [f"sitemap.xml: missing {u}" for u in sorted(want - listed)]
        bad += [f"sitemap.xml: lists {u}, which has no page" for u in sorted(listed - want)]
        if bad:
            print("build-evidence-pages --check: pages differ from config/applied-evidence.json:", file=sys.stderr)
            for b in bad:
                print(f"  - {b}", file=sys.stderr)
            return 1
        print(f"build-evidence-pages --check: OK, {len(expected)} files match their input")
        return 0
    for p in sorted(existing - expected):
        p.unlink()
    # sitemap.xml: drop every evidence <url>, then list the current pages, dated by the extraction.
    blocks = re.sub(r"\n  <url>\n    <loc>https://stigready\.com/applied/evidence/[^<]*</loc>.*?</url>", "", sitemap, flags=re.S)
    day = doc["extracted_at"][:10]
    add = "".join(f"\n  <url>\n    <loc>{u}</loc>\n    <lastmod>{day}</lastmod>\n    <changefreq>monthly</changefreq>\n"
                  f"    <priority>{'0.8' if u.endswith('/applied/evidence/') else '0.6'}</priority>\n  </url>"
                  for u in sorted(want))
    a.sitemap.write_text(blocks.replace("\n</urlset>", add + "\n</urlset>", 1), encoding="utf-8")
    for p, body in pages.items():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body)
    print(f"build-evidence-pages: wrote {len(pages)} files under {rel(a.out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
