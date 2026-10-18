"""The committed samples, dashboard and README must agree with what the code produces today."""
import json
import re
from pathlib import Path

from forensictriage import synthetic as syn
from forensictriage.config import load_config
from forensictriage.custody import verify_chain
from forensictriage.evaluate import evaluate

ROOT = Path(__file__).resolve().parent.parent
DASH = ROOT / "dashboard"
CASE = ROOT / "data" / "synthetic" / f"case-{syn.CASE_ID}"
REPORTS = ROOT / "reports"
STABLE_KEYS = ("summary", "findings", "narrative", "files", "timeline", "iocs", "carved", "deleted", "browser", "artifacts", "mitre", "rules", "window")


# ------------------------------------------------------------------ dashboard, static checks
def test_index_references_existing_assets():
    html = (DASH / "index.html").read_text()
    for ref in re.findall(r'(?:src|href)="([^"#:]+)"', html):
        assert (DASH / ref).exists(), ref


def test_no_inline_scripts_styles_or_handlers_so_csp_can_be_strict():
    html = (DASH / "index.html").read_text()
    assert not re.search(r"<script(?![^>]*\bsrc=)", html)
    assert not re.search(r"\son[a-z]+=", html)
    assert 'style="' not in html and "<style" not in html


def test_app_never_injects_html():
    js = (DASH / "app.js").read_text()
    for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert bad not in js, bad


def test_vercel_configs_are_valid_and_set_security_headers():
    for path in (DASH / "vercel.json", ROOT / "vercel.json"):
        cfg = json.loads(path.read_text())
        headers = {h["key"]: h["value"] for rule in cfg["headers"] for h in rule["headers"]}
        assert headers["X-Content-Type-Options"] == "nosniff" and headers["X-Frame-Options"] == "DENY"
        csp = headers["Content-Security-Policy"]
        assert "default-src 'self'" in csp and "script-src 'self'" in csp and "unsafe" not in csp
    assert json.loads((ROOT / "vercel.json").read_text())["outputDirectory"] == "dashboard"


def test_index_has_banner_and_every_panel_the_script_fills():
    html = (DASH / "index.html").read_text()
    js = (DASH / "app.js").read_text()
    assert "SYNTHETIC DATA" in html
    for needle in ("timeline", "f-table", "fl-table", "ioc-table", "carve-table", "custody-table", "integrity-status", "mitre-table", "rules-table", "drawer", "kpis", "chain-verify"):
        assert f'id="{needle}"' in html, needle
    for el_id in set(re.findall(r'\$\("([a-z0-9-]+)"\)', js)):
        assert f'id="{el_id}"' in html or el_id in ("kpi-critical",) or el_id.startswith(("chip-", "kpi-")), el_id


def test_dashboard_data_is_exactly_the_committed_report():
    assert (DASH / "data" / "case.json").read_bytes() == (REPORTS / "case_report.json").read_bytes()
    data = json.loads((DASH / "data" / "case.json").read_text())
    assert data["meta"]["synthetic"] is True and data["integrity"]["ok"] is True
    assert "/workspace/" not in (DASH / "data" / "case.json").read_text() and "/home/" not in (DASH / "data" / "case.json").read_text()


def test_the_javascript_chain_check_uses_the_same_canonical_rule_as_python():
    js = (DASH / "app.js").read_text()
    assert "function canon" in js and "sort()" in js and r"\\u" in js       # sorted keys, \uXXXX escapes (ensure_ascii)
    py = (ROOT / "forensictriage" / "custody.py").read_text()
    assert 'sort_keys=True, separators=(",", ":"), ensure_ascii=True' in py


# ------------------------------------------------------------------ committed samples match the code
def test_committed_synthetic_case_equals_a_fresh_generation(tmp_path):
    syn.generate(tmp_path / "fresh")
    fresh = {str(p.relative_to(tmp_path / "fresh")): p.read_bytes() for p in (tmp_path / "fresh").rglob("*") if p.is_file()}
    committed = {str(p.relative_to(CASE)): p.read_bytes() for p in CASE.rglob("*") if p.is_file()}
    assert fresh.keys() == committed.keys()
    assert [k for k in fresh if fresh[k] != committed[k]] == []


def test_committed_report_matches_a_fresh_run(report):
    committed = json.loads((REPORTS / "case_report.json").read_text())
    for key in STABLE_KEYS:
        assert report[key] == committed[key], key
    assert report["integrity"]["before"] == committed["integrity"]["before"]
    assert report["integrity"]["after"] == committed["integrity"]["after"]


def test_committed_reports_are_internally_consistent():
    rep = json.loads((REPORTS / "case_report.json").read_text())
    custody = json.loads((REPORTS / "custody_log.json").read_text())
    entries = custody["entries"] if isinstance(custody, dict) else custody
    assert verify_chain(entries)[0] and rep["integrity"]["custody_chain_ok"]
    manifest = json.loads((REPORTS / "evidence_manifest.json").read_text())
    assert manifest["digest_sha256"] == rep["integrity"]["before"]["manifest_sha256"] == rep["integrity"]["after"]["manifest_sha256"]
    md = (REPORTS / "case_report.md").read_text()
    assert "SYNTHETIC" in md and rep["meta"]["case_id"] in md
    for f in rep["findings"]:
        assert f["id"] in md
    carved = sorted(p.name for p in (REPORTS / "carved").iterdir())
    assert carved == sorted(c["name"] for c in rep["carved"]["files"])


def test_committed_evaluation_passes_and_is_reproducible(report, truth):
    ev = json.loads((REPORTS / "evaluation.json").read_text())
    fresh = evaluate(report, truth)
    assert ev["passed"] is True and fresh["passed"] is True
    assert ev["scenarios_total"] == fresh["scenarios_total"] and ev["scenarios_passed"] == fresh["scenarios_passed"]


def test_every_configured_rule_is_documented_in_the_readme():
    readme = (ROOT / "README.md").read_text()
    for rule in load_config()["rules"]:
        assert f"`{rule['id']}`" in readme, rule["id"]


def test_readme_numbers_match_the_committed_report():
    readme = (ROOT / "README.md").read_text()
    rep = json.loads((REPORTS / "case_report.json").read_text())
    s, ev = rep["summary"], json.loads((REPORTS / "evaluation.json").read_text())
    sev = s["by_severity"]
    assert f"findings {s['findings']} ({sev['critical']} critical, {sev['high']} high, {sev['medium']} medium, {sev['low']} low)" in readme
    assert f"{ev['scenarios_passed']}/{ev['scenarios_total']} scenarios" in readme
    assert f"carved {s['carved_complete']} complete + {s['carved_partial']} partial" in readme
    assert rep["integrity"]["before"]["manifest_sha256"][:16] in readme
