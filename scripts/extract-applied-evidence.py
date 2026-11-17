#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 StigReady
# SPDX-License-Identifier: LicenseRef-StigReady-Proprietary
"""Summarise each Applied version's build evidence bundle for its public evidence page. Read-only.

Runs where the release store is mounted. For every Applied row of catalog.json it opens the bundle of that row's
version and writes one summary record: the OpenSCAP score and counts, the scan time, profile and SCAP Security Guide
version, the exemptions with their reasons, the refined (tailored) values, the CVE counts by severity, the SBOM package
count, and the signed manifest's digests. It reads nothing else and writes only under --out.

Signed and unsigned values are kept apart. A bundle's provenance.json is the manifest its cosign signature covers, and
it lists a SHA-256 digest per file. Every file this script reads a number from is hashed and compared with that digest
(`signed: true` on the record, or a problem when it differs). evidence.json is not in the manifest, so the exemption
reasons and customer actions taken from it are marked `source: build-record` and the page says so.

The record for a version is written only if the bundle is that version (evidence.json version and AMI equal the row's
and, with --live-amis, the AMI the live listing ships). Anything else is listed under `problems` and the generator
refuses to build a page from a record that has one.

    python3 -I scripts/extract-applied-evidence.py --store <release store> --catalog catalog.json \
        --live-amis live-amis.json --out <dir>

<dir>/applied-evidence-extract.json is the summary; <dir>/sbom/<cell>-v<version>.cdx.json is each bundle's CycloneDX
SBOM, byte for byte; <dir>/sig/<cell>-v<version>/ holds provenance.json and its .sig for a cosign check elsewhere.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
import xml.etree.ElementTree as ET
from pathlib import Path

XCCDF = "{http://checklists.nist.gov/xccdf/1.2}"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
# Exemption fields that may be published. The record's decision and POA&M-link fields point at internal documents.
EXEMPTION_FIELDS = ("rule", "title", "disa", "class", "why", "customer_action")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def store_dir(os_key: str, arch: str) -> str:
    """catalog os_key + arch -> the release store's image directory (rhel-9 arm64 -> rhel9-aarch64)."""
    name = os_key.replace("-", "").replace(".", "")
    return name + ("-aarch64" if arch == "arm64" else "")


def scorecard(path: Path) -> dict:
    """openscap-score.txt: `OpenSCAP: pass=N fail=N score=N% (target N%)`. The other counts come from results.xml."""
    m = re.search(r"OpenSCAP:\s*pass=(\d+)\s+fail=(\d+)\s+score=([\d.]+)%", path.read_text(encoding="utf-8"))
    if not m:
        raise ValueError("openscap-score.txt has no 'OpenSCAP: pass= fail= score=' line")
    p, f, s = m.groups()
    return {"pass": int(p), "fail": int(f), "score": float(s)}


def results_xml(path: Path) -> dict:
    """SSG version, profile, scan start/end and the rule-result counts of the one TestResult."""
    out: dict = {"results": {}}
    profiles: dict[str, str] = {}
    defaults: dict[str, str] = {}
    depth = 0
    for event, el in ET.iterparse(str(path), events=("start", "end")):
        if event == "start":
            depth += 1
            if el.tag == XCCDF + "Benchmark" and "benchmark_id" not in out:
                out["benchmark_id"] = el.get("id")
            elif el.tag == XCCDF + "TestResult":
                out["start_time"] = el.get("start-time")
                out["end_time"] = el.get("end-time")
            continue
        depth -= 1
        if el.tag == XCCDF + "version" and depth == 1 and "ssg_version" not in out:
            out["ssg_version"] = (el.text or "").strip()
        elif el.tag == XCCDF + "Profile":
            t = el.find(XCCDF + "title")
            profiles[el.get("id")] = (t.text or "").strip() if t is not None else ""
            el.clear()
        elif el.tag == XCCDF + "rule-result":
            r = el.find(XCCDF + "result")
            k = (r.text or "").strip() if r is not None else "?"
            out["results"][k] = out["results"].get(k, 0) + 1
            el.clear()
        elif el.tag == XCCDF + "TestResult":
            p = el.find(XCCDF + "profile")
            out["profile_id"] = p.get("idref") if p is not None else None
        elif el.tag == XCCDF + "Value":
            for v in el.findall(XCCDF + "value"):
                if not v.get("selector"):
                    defaults[el.get("id", "")] = v.text or ""
            el.clear()
        elif el.tag in (XCCDF + "Rule", XCCDF + "Group"):
            el.clear()
    out["profile_titles"] = profiles
    out["value_defaults"] = defaults
    return out


def trivy(path: Path) -> dict:
    """Trivy's report, counted per result class: OS packages (os-pkgs) and language packages (lang-pkgs, e.g. the Go
    binaries of amazon-ssm-agent) are different populations and are never summed. Per class: packages Trivy detected,
    package findings, and distinct CVE ids by severity, with how many of those had a fixed version listed."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    sev_rank = {s: i for i, s in enumerate(SEVERITIES)}
    classes: dict[str, dict] = {}
    for res in doc.get("Results") or []:
        cls = res.get("Class") or "unknown"
        acc = classes.setdefault(cls, {"targets": 0, "packages": 0, "findings": 0, "_seen": {}})
        acc["targets"] += 1
        acc["packages"] += len(res.get("Packages") or [])
        for v in res.get("Vulnerabilities") or []:
            acc["findings"] += 1
            sev = (v.get("Severity") or "UNKNOWN").upper()
            sev = sev if sev in sev_rank else "UNKNOWN"
            cur = acc["_seen"].setdefault(v.get("VulnerabilityID"), {"severity": sev, "fixable": False})
            if sev_rank[sev] < sev_rank[cur["severity"]]:
                cur["severity"] = sev
            if v.get("FixedVersion"):
                cur["fixable"] = True
    for acc in classes.values():
        seen = acc.pop("_seen")
        acc["distinct"] = {s.lower(): 0 for s in SEVERITIES}
        acc["distinct_fixable"] = {s.lower(): 0 for s in SEVERITIES}
        for rec in seen.values():
            acc["distinct"][rec["severity"].lower()] += 1
            if rec["fixable"]:
                acc["distinct_fixable"][rec["severity"].lower()] += 1
    os_meta = ((doc.get("Metadata") or {}).get("OS") or {})
    return {
        "scanner": "Trivy", "scanner_version": ((doc.get("Trivy") or {}).get("Version")),
        "created_at": doc.get("CreatedAt"), "os_detected": f"{os_meta.get('Family', '')} {os_meta.get('Name', '')}".strip(),
        "classes": classes, "db": doc.get("StigReadyTrivyDB"),
    }


def poam_rules(path: Path) -> list[str]:
    return re.findall(r"^\|\s*`([^`]+)`\s*\|", path.read_text(encoding="utf-8"), flags=re.M)


def cosign_ok(cosign_pub: Path | None, bundle: Path) -> bool | None:
    """cosign verify-blob of provenance.json against its .sig with the given public key; None when no key is given."""
    if cosign_pub is None:
        return None
    r = subprocess.run(["cosign", "verify-blob", "--insecure-ignore-tlog", "--key", str(cosign_pub), "--signature",
                        str(bundle / "provenance.json.sig"), str(bundle / "provenance.json")], capture_output=True)
    return r.returncode == 0


def one(row: dict, store: Path, live_ami: str | None, out: Path, cosign_pub: Path | None = None) -> dict:
    cell = f"{row['os_key']}-{row['arch']}-{row['profile']}"
    ver = row["version"]
    bundle = store / store_dir(row["os_key"], row["arch"]) / row["profile"] / f"v{ver}" / "evidence"
    rec: dict = {"cell": cell, "os": row["os"], "os_key": row["os_key"], "arch": row["arch"],
                 "profile": row["profile"], "benchmark": row.get("benchmark"), "version": ver, "problems": []}
    P = rec["problems"]
    if not (bundle / "evidence.json").is_file() or not (bundle / "provenance.json").is_file():
        P.append("no bundle (evidence.json or provenance.json missing) for this version")
        return rec
    ev = json.loads((bundle / "evidence.json").read_text(encoding="utf-8"))
    prov = json.loads((bundle / "provenance.json").read_text(encoding="utf-8"))
    digests = prov.get("digests") or {}

    if ev.get("version") != ver or prov.get("version") != ver:
        P.append(f"bundle version {ev.get('version')}/{prov.get('version')} is not {ver}")
    if ev.get("profile") != row["profile"]:
        P.append(f"bundle profile {ev.get('profile')} is not {row['profile']}")
    ami = (ev.get("amis") or {}).get("commercial") or ev.get("ami")
    if ami != (prov.get("ami") or {}).get("commercial"):
        P.append("evidence.json and the signed manifest name different AMIs")
    if live_ami is not None and ami != live_ami:
        P.append("the bundle's AMI is not the AMI the live listing ships")
    rec["ami_matches_live_listing"] = live_ami is not None and ami == live_ami
    rec["fips"] = bool(ev.get("fips")) and bool(prov.get("fips"))
    if rec["fips"] != (row["profile"] == "stig"):
        P.append(f"fips={rec['fips']} on profile {row['profile']} (FIPS is on exactly the stig profile)")
    rec["build_timestamp"] = ev.get("timestamp")
    rec["signature"] = {"status": (ev.get("provenance") or {}).get("status"), "signed_at": prov.get("signed_at"),
                        "manifest_files": len(digests), "cosign_verified": cosign_ok(cosign_pub, bundle)}
    if rec["signature"]["cosign_verified"] is False:
        P.append("the cosign signature on provenance.json does not verify")

    def signed(rel: str) -> Path | None:
        f = bundle / rel
        if not f.is_file():
            return None
        if rel not in digests:
            P.append(f"{rel} is not in the signed manifest")
        elif sha256(f) != digests[rel]:
            P.append(f"{rel} does not match its signed digest")
        return f

    rec["signed_digests"] = {}
    sc = signed("openscap/openscap-score.txt")
    rx = signed("openscap/results.xml")
    if sc is None or rx is None:
        P.append("openscap-score.txt or results.xml missing")
        return rec
    rec["scorecard"] = scorecard(sc)
    rec["xccdf"] = results_xml(rx)
    for k in ("notapplicable", "notchecked"):
        rec["scorecard"][k] = rec["xccdf"]["results"].get(k, 0)
    for k in ("pass", "fail"):
        if rec["xccdf"]["results"].get(k, 0) != rec["scorecard"][k]:
            P.append(f"results.xml {k}={rec['xccdf']['results'].get(k, 0)} but the scorecard says {rec['scorecard'][k]}")
    og = (ev.get("gates") or {}).get("openscap") or {}
    rec["gate"] = {k: og.get(k) for k in ("status", "score", "pass", "fail", "floor", "enforce",
                                           "exempt_failures", "nonexempt_failures")}
    if og.get("score") != rec["scorecard"]["score"]:
        P.append(f"evidence.json score {og.get('score')} is not the signed scorecard's {rec['scorecard']['score']}")
    if og.get("status") != "pass":
        P.append(f"OpenSCAP gate status {og.get('status')}")
    for rel in ("openscap/openscap-score.txt", "openscap/results.xml"):
        rec["signed_digests"][rel] = digests.get(rel)

    ex = [{k: e.get(k) for k in EXEMPTION_FIELDS} for e in og.get("exemptions") or [] if e.get("result") == "fail"]
    rec["exemptions"] = sorted(ex, key=lambda e: (e["class"] or "", e["rule"]))
    if len(ex) != rec["scorecard"]["fail"]:
        P.append(f"{len(ex)} failing exemptions but {rec['scorecard']['fail']} failing rules: a failure is unexplained")
    if any(not e.get("why") for e in ex):
        P.append("an exemption has no reason")
    pm = signed("poam.md")
    if pm is not None:
        rec["signed_digests"]["poam.md"] = digests.get("poam.md")
        if sorted(poam_rules(pm)) != sorted(e["rule"] for e in ex):
            P.append("the signed POA&M and the build record list different exempt rules")
    rec["poam_signed"] = pm is not None
    tl = signed("openscap/tailoring.xml")
    tailoring_text = tl.read_text(encoding="utf-8") if tl else ""
    rec["tailoring"] = []
    for t in og.get("tailoring") or []:
        if tl is None or str(t.get("value")) not in tailoring_text.replace("&amp;", "&"):
            P.append(f"refined value {t.get('variable')} is not in the signed tailoring.xml")
        # The reason text in the build record names internal records, so it is not published. The page shows the
        # value next to the SSG default it replaces, both from signed files (tailoring.xml, results.xml).
        default = rec["xccdf"]["value_defaults"].get(f"xccdf_org.ssgproject.content_value_{t.get('variable')}")
        if default is None:
            P.append(f"no SSG default for refined value {t.get('variable')} in results.xml")
        rec["tailoring"].append({"variable": t.get("variable"), "value": t.get("value"), "ssg_default": default})
    if tl is not None:
        rec["signed_digests"]["openscap/tailoring.xml"] = digests.get("openscap/tailoring.xml")
    # The scored profile: the SSG profile itself, or the tailoring profile that extends it with the refined values.
    titles = rec["xccdf"].pop("profile_titles")
    rec["xccdf"].pop("value_defaults")
    scored = rec["xccdf"].get("profile_id")
    m = re.search(r'<(?:\w+:)?Profile[^>]*\bid="%s"[^>]*\bextends="([^"]+)"' % re.escape(scored or ""), tailoring_text) \
        or re.search(r'<(?:\w+:)?Profile[^>]*\bextends="([^"]+)"[^>]*\bid="%s"' % re.escape(scored or ""), tailoring_text)
    base = m.group(1) if m else scored
    rec["ssg_profile"] = {"id": base, "title": titles.get(base, ""), "tailored": bool(m), "scored_id": scored}
    if not rec["ssg_profile"]["title"]:
        P.append(f"the SSG profile {base} is not in results.xml")
    if bool(m) != bool(rec["tailoring"]):
        P.append("the scored profile and the refined-value list disagree on whether the profile is tailored")

    tg = (ev.get("gates") or {}).get("trivy") or {}
    tv = signed("trivy-cve.json")
    if tv is None:
        rec["cve"] = None
    else:
        rec["cve"] = trivy(tv)
        rec["cve"]["gate"] = {k: tg.get(k) for k in ("status", "critical", "high", "medium", "fixable_critical",
                                                     "fixable_high", "unfixed_critical", "unfixed_high")}
        rec["signed_digests"]["trivy-cve.json"] = digests.get("trivy-cve.json")

    sb = signed("sbom.cdx.json")
    if sb is None:
        P.append("no CycloneDX SBOM")
    else:
        doc = json.loads(sb.read_text(encoding="utf-8"))
        rec["sbom"] = {"format": f"CycloneDX {doc.get('specVersion', '?')} JSON", "components": len(doc.get("components") or []),
                       "sha256": digests.get("sbom.cdx.json"), "bytes": sb.stat().st_size}
        rec["signed_digests"]["sbom.cdx.json"] = digests.get("sbom.cdx.json")
        (out / "sbom").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(sb, out / "sbom" / f"{cell}-v{ver}.cdx.json")
    sig = out / "sig" / f"{cell}-v{ver}"
    sig.mkdir(parents=True, exist_ok=True)
    for name in ("provenance.json", "provenance.json.sig"):
        if (bundle / name).is_file():
            shutil.copyfile(bundle / name, sig / name)
        else:
            P.append(f"{name} missing")
    return rec


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--store", required=True, type=Path)
    ap.add_argument("--catalog", required=True, type=Path)
    ap.add_argument("--live-amis", type=Path, help='{"<os_key>:<arch>:<profile>": {"version": "v1.0.2", "ami": "ami-..."}}')
    ap.add_argument("--cosign-pub", type=Path, help="public key: verify each bundle's signature with cosign")
    ap.add_argument("--out", required=True, type=Path)
    a = ap.parse_args(argv)
    rows = [p for p in json.loads(a.catalog.read_text())["products"]
            if p["line"] == "stigapplied" and p["availability"] == "available"]
    live = json.loads(a.live_amis.read_text()) if a.live_amis else {}
    a.out.mkdir(parents=True, exist_ok=True)
    recs = []
    for row in sorted(rows, key=lambda r: (r["os_key"], r["arch"], r["profile"])):
        key = f"{row['os_key']}:{row['arch']}:{row['profile']}"
        lv = live.get(key)
        if a.live_amis and (lv is None or lv.get("version") != f"v{row['version']}"):
            recs.append({"cell": key, "version": row["version"], "problems": [f"live listing version {lv} is not v{row['version']}"]})
            continue
        try:
            recs.append(one(row, a.store, lv["ami"] if lv else None, a.out, a.cosign_pub))
        except Exception as e:  # one bad bundle must not hide the others; it is recorded, never skipped
            recs.append({"cell": key, "version": row["version"], "problems": [f"{type(e).__name__}: {e}"]})
        print(f"{key} v{row['version']}: {len(recs[-1]['problems'])} problem(s)", file=sys.stderr)
    head = {"schema": 1, "extracted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "catalog_generated": json.loads(a.catalog.read_text()).get("generated"),
            "live_listings_checked": bool(a.live_amis), "signatures_checked": a.cosign_pub is not None}
    (a.out / "applied-evidence-extract.json").write_text(json.dumps({**head, "cells": recs}, indent=1) + "\n")
    bad = [r for r in recs if r["problems"]]
    print(f"{len(recs)} versions, {len(bad)} with problems", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
