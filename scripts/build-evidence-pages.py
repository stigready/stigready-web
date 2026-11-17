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
    "owner-cloud-usability": "Cloud usability: risk accepted",
}
PROFILE_NAME = {"cis-l1": "CIS Benchmark Level 1", "cis-l2": "CIS Benchmark Level 2", "stig": "DISA STIG"}
OS_LONG = {"rhel": "Red Hat Enterprise Linux", "rocky": "Rocky Linux", "alma": "AlmaLinux", "ubuntu": "Ubuntu"}
# The scanner the build uses reports nothing for these OS releases: a zero there would read as "no CVEs".
NO_CVE_SCAN = ("rhel-10",)
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
        .ev ul { list-style: disc; padding-left: 1.25rem; margin: 0 0 .75rem; }
    """

problems: list[str] = []


def e(s) -> str:
    return html.escape("" if s is None else str(s), quote=True)


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


def product_name(c: dict) -> str:
    return f"StigReady Applied {c['os']} {PROFILE_NAME[c['profile']]} ({c['arch']})"


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


def check_record(c: dict, cat: dict) -> None:
    where = f"{c.get('cell')} v{c.get('version')}"
    for p in c.get("problems") or []:
        problems.append(f"{where}: extract problem: {p}")
    if c.get("problems"):
        return
    row = cat.get((c["os_key"], c["arch"], c["profile"]))
    if row is None or row.get("line") != "stigapplied" or row.get("availability") != "available":
        problems.append(f"{where}: not an available Applied row in catalog.json")
        return
    if row.get("version") != c["version"]:
        problems.append(f"{where}: catalog.json sells v{row.get('version')}")
    if row.get("score") != c["scorecard"]["score"]:
        problems.append(f"{where}: catalog.json score {row.get('score')} is not the signed score {c['scorecard']['score']}")
    sc = c["scorecard"]
    if sc["pass"] + sc["fail"] == 0 or round(100 * sc["pass"] / (sc["pass"] + sc["fail"]), 1) != sc["score"]:
        problems.append(f"{where}: score {sc['score']} is not pass/(pass+fail)")
    if c["fips"] != (c["profile"] == "stig"):
        problems.append(f"{where}: FIPS {c['fips']} on profile {c['profile']}")
    if not c.get("ami_matches_live_listing"):
        problems.append(f"{where}: the bundle was not matched to the live listing's AMI")
    if (c.get("signature") or {}).get("cosign_verified") is not True:
        problems.append(f"{where}: signature not verified at extraction")
    if len(c["exemptions"]) != sc["fail"] or c["gate"].get("nonexempt_failures") != 0:
        problems.append(f"{where}: {sc['fail']} failing rules but {len(c['exemptions'])} exemptions")
    for x in c["exemptions"]:
        if x["class"] not in CLASS_LABEL:
            problems.append(f"{where}: exemption class {x['class']!r} has no public label")
    if c["os_key"].startswith(NO_CVE_SCAN):
        if c.get("cve") and c["cve"].get("package_findings"):
            problems.append(f"{where}: the scanner reported findings on an OS listed as unscannable; review NO_CVE_SCAN")
    elif not c.get("cve"):
        problems.append(f"{where}: no CVE scan in the bundle")
    if not c.get("sbom"):
        problems.append(f"{where}: no SBOM")


def exemption_rows(c: dict) -> str:
    rows = []
    for x in c["exemptions"]:
        disa = ", ".join(x.get("disa") or []) or "—"
        rows.append(
            f"<tr><td><code>{e(x['rule'])}</code><br><span class=\"muted\">{e(x['title'])}</span></td>"
            + (f"<td>{e(disa)}</td>" if c["profile"] == "stig" else "")
            + f"<td>{e(CLASS_LABEL[x['class']])}</td><td>{e(x['why'])}</td><td>{e(x['customer_action'])}</td></tr>")
    disa_h = "<th>STIG ID</th>" if c["profile"] == "stig" else ""
    return (f"<div class=\"tbl\"><table><thead><tr><th>Rule</th>{disa_h}<th>Category</th><th>Why it fails in the image"
            f"</th><th>What you do</th></tr></thead><tbody>\n" + "\n".join(rows) + "\n</tbody></table></div>")


def cve_section(c: dict) -> str:
    if c["os_key"].startswith(NO_CVE_SCAN):
        return ("<p>This version's evidence has no CVE scan. The build's scanner (Trivy) does not cover "
                f"{e(os_long(c['os_key']))} packages, so its empty result for this image is not shown as a count: "
                "zero findings from it would not mean the image has no known CVEs.</p>")
    v = c["cve"]
    sev = ("critical", "high", "medium", "low")
    cells = "".join(f"<td>{v['distinct'][s]}</td>" for s in sev)
    fix = "".join(f"<td>{v['distinct_fixable'][s]}</td>" for s in sev)
    unknown = v["distinct"].get("unknown", 0)
    return (f"<p>Scanned with Trivy {e(v['scanner_version'])} in the image build on {utc(v['created_at'])}. Counts are "
            "distinct CVE identifiers in the installed OS packages at that date; CVEs published later are not "
            "counted.</p>\n<div class=\"tbl\"><table><thead><tr><th></th><th>Critical</th><th>High</th><th>Medium</th>"
            f"<th>Low</th></tr></thead><tbody>\n<tr><td>CVEs found</td>{cells}</tr>\n<tr><td>Of those, with a fixed "
            f"package published at scan time</td>{fix}</tr>\n</tbody></table></div>\n"
            + (f"<p class=\"muted\">{unknown} more had no severity rating.</p>\n" if unknown else "")
            + "<p class=\"muted\">The per-CVE list is in the full evidence bundle, on request.</p>")


def version_page(c: dict, row: dict) -> str:
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
            <div class="tile"><div class="k">Rules passed</div><div class="v">{sc['pass']}</div></div>
            <div class="tile"><div class="k">Rules failed</div><div class="v">{sc['fail']}</div></div>
            <div class="tile"><div class="k">Not applicable</div><div class="v">{sc['notapplicable']}</div></div>
            <div class="tile"><div class="k">Not checked</div><div class="v">{sc['notchecked']}</div></div>
        </div>

        <h2>How it was scored</h2>
        <ul>
            <li>Scanned with OpenSCAP in the image build on {utc(x['start_time'])}.</li>
            <li>Content: SCAP Security Guide {e(x['ssg_version'])}, profile “{e(prof['title'])}”
                (<code>{e(prof['id'])}</code>){f", with the refined value{'s' if len(c['tailoring']) != 1 else ''} listed below" if prof['tailored'] else ", as published"}.</li>
            <li>Score = rules passed ÷ (rules passed + rules failed). Every rule listed under Exemptions failed in the
                scan and counts as a failure in the score. Not-applicable and not-checked rules are not scored.</li>
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
        <p>{e(c['sbom']['format'])}, {c['sbom']['components']} components:
        <a href="sbom.cdx.json.gz">sbom.cdx.json.gz</a> (gzip). Uncompressed, its SHA-256 is the one in the signed
        manifest: <code>{e(c['sbom']['sha256'].removeprefix('sha256:'))}</code>.</p>

        <h2>Signature</h2>
        <p>The bundle's manifest lists a SHA-256 digest for each of its {c['signature']['manifest_files']} files and was
        signed with cosign on {utc(c['signature']['signed_at'])}. When this page was generated the signature verified
        and each file this page summarises matched its digest:</p>
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
        <th>OpenSCAP score</th><th>Evidence</th></tr></thead><tbody>
""")
    for c in sorted(cells, key=lambda c: (c["os_key"], c["profile"], c["arch"])):
        out.append(f"""        <tr><td>{e(c['os'])}</td><td>{e(c['arch'])}</td><td>{e(PROFILE_NAME[c['profile']])}</td><td>v{e(c['version'])}</td><td>{c['scorecard']['score']:.1f}%</td><td><a href="/{page_rel(c)}">Summary</a> · <a href="/{product_rel(c)}">All versions</a></td></tr>
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
            pages[d / "index.html"] = version_page(c, cat[(c["os_key"], c["arch"], c["profile"])]).encode()
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
    existing = {p for p in a.out.rglob("index.html")} if a.out.is_dir() else set()
    if a.check:
        bad = [rel(p) for p in sorted(expected) if not p.is_file() or p.read_bytes() != pages[p]]
        bad += [f"{rel(p)} (stale: no record)" for p in sorted(existing - expected)]
        if bad:
            print("build-evidence-pages --check: pages differ from config/applied-evidence.json:", file=sys.stderr)
            for b in bad:
                print(f"  - {b}", file=sys.stderr)
            return 1
        print(f"build-evidence-pages --check: OK, {len(expected)} pages match their input")
        return 0
    for p in sorted(existing - expected):
        p.unlink()
    for p, body in pages.items():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body)
    print(f"build-evidence-pages: wrote {len(pages)} files under {rel(a.out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
