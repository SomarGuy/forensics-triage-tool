"""Compare a case report with ``ground_truth.json``: did triage find what was planted, and nothing else?"""
from __future__ import annotations

import json
from typing import Dict, List

from .config import SEVERITY_ORDER


def _blob(f: dict) -> str:
    return " ".join([f["title"], f["summary"], " ".join(f["files"]), " ".join(f["evidence"])]).lower()


def _matches(f: dict, exp: dict) -> bool:
    return f["rule"] == exp["rule"] and exp["contains"].lower() in _blob(f)


def evaluate(report: dict, truth: dict) -> dict:
    findings = report["findings"]
    scenarios: List[dict] = []
    for exp in truth["expected_findings"]:
        hits = [f for f in findings if _matches(f, exp)]
        ok = bool(hits) and any(SEVERITY_ORDER[f["severity"]] <= SEVERITY_ORDER[exp["min_severity"]] for f in hits)
        scenarios.append({"id": exp["id"], "scenario": exp["scenario"], "rule": exp["rule"], "passed": ok,
                          "finding": hits[0]["id"] if hits else None, "severity": hits[0]["severity"] if hits else None,
                          "detail": "" if ok else ("no matching finding" if not hits else f"severity {hits[0]['severity']} below {exp['min_severity']}")})
    must_not: List[dict] = []
    for m in truth["must_not_flag"]:
        bad = [f for f in findings if f["rule"] == m["rule"] and m["path"].lower() in _blob(f)]
        must_not.append({"rule": m["rule"], "path": m["path"], "why": m["why"], "passed": not bad, "finding": bad[0]["id"] if bad else None})
    unexpected = [f["id"] + " " + f["title"] for f in findings if not any(_matches(f, e) for e in truth["expected_findings"])]

    iocs = report["iocs"]
    ioc_rows = []
    for e in truth["expected_iocs"]:
        ok = any(i["type"] == e["type"] and i["value"] == e["value"] and (not e.get("scope") or i["scope"] == e["scope"]) for i in iocs)
        ioc_rows.append({"type": e["type"], "value": e["value"], "passed": ok})
    noise = [i["value"] for i in iocs if any(n in i["value"] for n in truth["must_not_be_iocs"])]

    carved = report["carved"]
    stats = report["carved"]["stats"][0] if report["carved"]["stats"] else {}
    exp_c = truth["expected_carving"]
    carving = []
    for key in ("complete", "partial", "rejected"):
        carving.append({"check": f"{key} = {exp_c[key]}", "passed": stats.get(key) == exp_c[key], "actual": stats.get(key)})
    carving.append({"check": f"nested headers skipped >= {exp_c['nested_skipped_at_least']}", "passed": stats.get("nested_skipped", 0) >= exp_c["nested_skipped_at_least"], "actual": stats.get("nested_skipped")})
    offsets = {c["offset"] for c in carved["files"]}
    for kind, off in exp_c["offsets"].items():
        carving.append({"check": f"{kind} carved at offset {off}", "passed": off in offsets, "actual": sorted(offsets)})
    z = exp_c["zip_sha256_equals_file"]
    zip_ok = any(c["sha256"] == z["sha256"] and c["matches_file"] == z["file"] for c in carved["files"])
    carving.append({"check": "carved ZIP is byte-identical to the renamed file on disk", "passed": zip_ok, "actual": z["file"]})

    usb = sorted(d["serial"] for d in report["artifacts"]["usb_devices"])
    counts = []
    for k, v in truth["expected_counts"].items():
        actual = {"files": report["summary"]["files"], "recycle_records": report["summary"]["recycle_records"], "mft_deleted": report["summary"]["mft_deleted"],
                  "known_bad": report["summary"]["known_bad"], "known_good": report["summary"]["known_good"]}[k]
        counts.append({"check": f"{k} = {v}", "passed": actual == v, "actual": actual})
    integrity_ok = report["integrity"]["ok"] and report["integrity"]["custody_chain_ok"]

    passed = (all(s["passed"] for s in scenarios) and all(m["passed"] for m in must_not) and not unexpected and all(r["passed"] for r in ioc_rows)
              and not noise and all(c["passed"] for c in carving) and usb == sorted(truth["expected_usb_serials"]) and all(c["passed"] for c in counts) and integrity_ok)
    return {
        "synthetic": True, "case_id": truth["case_id"], "passed": passed,
        "scenarios": scenarios, "scenarios_passed": sum(s["passed"] for s in scenarios), "scenarios_total": len(scenarios),
        "must_not_flag": must_not, "must_not_passed": sum(m["passed"] for m in must_not), "must_not_total": len(must_not),
        "unexpected_findings": unexpected, "iocs": ioc_rows, "noise_iocs": noise, "carving": carving,
        "usb_serials": usb, "counts": counts, "integrity_ok": integrity_ok,
    }


def format_evaluation(ev: dict) -> str:
    lines = [f"Evaluation against ground truth (case {ev['case_id']}, SYNTHETIC data; graded against my own storyline)"]
    for s in ev["scenarios"]:
        lines.append(f"  [{'PASS' if s['passed'] else 'FAIL'}] {s['id']} {s['scenario']} ({s['rule']}" + (f" -> {s['finding']} {s['severity']}" if s["finding"] else "") + ")" + (f"  {s['detail']}" if s["detail"] else ""))
    for m in ev["must_not_flag"]:
        lines.append(f"  [{'PASS' if m['passed'] else 'FAIL'}] must not flag {m['rule']} on {m['path']}: {m['why']}")
    for c in ev["carving"] + ev["counts"]:
        lines.append(f"  [{'PASS' if c['passed'] else 'FAIL'}] {c['check']}")
    for i in ev["iocs"]:
        lines.append(f"  [{'PASS' if i['passed'] else 'FAIL'}] IOC {i['type']} {i['value']}")
    lines.append(f"  unexpected findings: {len(ev['unexpected_findings'])}" + ("".join("\n    - " + u for u in ev["unexpected_findings"])))
    lines.append(f"  noise indicators leaked: {len(ev['noise_iocs'])}; integrity verified: {ev['integrity_ok']}")
    lines.append(f"  RESULT: {ev['scenarios_passed']}/{ev['scenarios_total']} scenarios, {ev['must_not_passed']}/{ev['must_not_total']} must-not-flag checks, "
                 f"{len(ev['unexpected_findings'])} unexpected -> {'ALL CHECKS PASSED' if ev['passed'] else 'FAILED'}")
    return "\n".join(lines)
