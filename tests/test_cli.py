import json
import os
import shutil
from pathlib import Path

import pytest

from forensictriage import cli
from forensictriage import triage as triage_mod
from forensictriage import synthetic as syn


def run(capsys, *argv):
    code = cli.main(list(argv))
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def test_triage_with_case_dir_prints_summary_and_writes_reports(capsys, synth_dir, tmp_path):
    out = tmp_path / "out"
    code, text, _ = run(capsys, "triage", "--case", str(synth_dir), "--out", str(out), "--no-colour")
    assert code == 0
    assert "Case FT-2026-0417  [SYNTHETIC DATA]" in text and "VERIFIED UNCHANGED" in text and "FND-001 [CRITICAL]" in text
    for name in ("case_report.json", "case_report.md", "custody_log.json", "evidence_manifest.json"):
        assert (out / name).is_file()


def test_min_severity_filters_the_printed_list_only(capsys, synth_dir, tmp_path):
    code, text, _ = run(capsys, "triage", "--case", str(synth_dir / "case.json"), "--out", str(tmp_path / "o"), "--min-severity", "critical")
    assert code == 0 and "FND-001" in text and "FND-002" not in text
    assert json.loads((tmp_path / "o" / "case_report.json").read_text())["summary"]["findings"] == 20


def test_fail_on_sets_exit_status_2(capsys, synth_dir, tmp_path):
    assert run(capsys, "triage", "--case", str(synth_dir), "--out", str(tmp_path / "a"), "--fail-on", "critical")[0] == 2
    # a folder with nothing noteworthy passes any threshold
    root = tmp_path / "plain"
    root.mkdir()
    (root / "a.txt").write_text("hello")
    assert run(capsys, "triage", "--root", str(root), "--out", str(tmp_path / "b"), "--fail-on", "low")[0] == 0


def test_integrity_failure_exit_status_4(capsys, synth_dir, tmp_path, monkeypatch):
    case = tmp_path / "case"
    shutil.copytree(synth_dir, case)
    victim = case / "evidence" / syn.HOME / "Documents" / "todo.txt"
    orig = triage_mod.detect_type
    state = {"n": 0}

    def evil(path, head=None):
        if state["n"] == 0:
            state["n"] = 1
            victim.write_bytes(b"changed")
        return orig(path, head)
    monkeypatch.setattr(triage_mod, "detect_type", evil)
    code, text, _ = run(capsys, "triage", "--case", str(case), "--out", str(tmp_path / "o"))
    assert code == 4 and "CHANGED DURING ANALYSIS" in text


def test_adhoc_options_and_dashboard_copy(capsys, synth_dir, tmp_path):
    out, dash = tmp_path / "o", tmp_path / "d" / "case.json"
    code, text, _ = run(capsys, "triage", "--root", str(synth_dir / "evidence"), "--raw", str(synth_dir / "unallocated" / "unallocated.dd"),
                        "--metadata", str(synth_dir / "artifacts" / "mft_export.csv"), "--prefetch", str(synth_dir / "artifacts" / "prefetch_export.json"),
                        "--registry", str(synth_dir / "artifacts" / "registry_export.csv"), "--known-bad", str(synth_dir / "hashsets" / "known_bad.txt"),
                        "--known-good", str(synth_dir / "hashsets" / "known_good.txt"), "--case-id", "MY-1", "--examiner", "Tester",
                        "--acquired-at", "2026-03-16 08:30:00", "--out", str(out), "--dashboard-json", str(dash))
    assert code == 0 and "Case MY-1" in text and "SYNTHETIC" not in text
    rep = json.loads(dash.read_text())
    assert rep["meta"]["examiner"] == "Tester" and rep["summary"]["findings"] == 20 and rep["meta"]["synthetic"] is False


def test_case_flag_can_be_overridden_by_root(capsys, synth_dir, tmp_path):
    code, text, _ = run(capsys, "triage", "--case", str(synth_dir), "--root", str(synth_dir / "evidence" / "Users"), "--out", str(tmp_path / "o"))
    assert code == 0 and "Case FT-2026-0417" in text


@pytest.mark.parametrize("argv,message", [
    (["triage", "--out", "{out}"], "give --case or --root"),
    (["triage", "--root", "{missing}", "--out", "{out}"], "not a directory"),
    (["triage", "--case", "{missing}", "--out", "{out}"], "cannot read case file"),
    (["triage", "--root", "{root}", "--acquired-at", "last tuesday", "--out", "{out}"], "--acquired-at"),
    (["triage", "--root", "{root}", "--config", "{missing}", "--out", "{out}"], "configuration file not found"),
])
def test_usage_errors_exit_3_with_a_message(capsys, tmp_path, argv, message):
    root = tmp_path / "root"
    root.mkdir()
    fill = {"out": str(tmp_path / "out"), "missing": str(tmp_path / "missing"), "root": str(root)}
    code, _out, err = run(capsys, *[a.format(**fill) for a in argv])
    assert code == 3 and message in err


def test_list_rules_and_validate_config(capsys, tmp_path):
    code, text, _ = run(capsys, "list-rules")
    assert code == 0 and "FT-003" in text and "T1070.006" in text and text.count("\n") == 15
    code, text, _ = run(capsys, "validate-config")
    assert code == 0 and text.startswith("OK: 15 rules")
    bad = tmp_path / "bad.json"
    cfg = json.loads(Path(cli.DEFAULT_CONFIG_PATH).read_text())
    cfg["rules"][0]["severity"] = "urgent"
    bad.write_text(json.dumps(cfg))
    code, _o, err = run(capsys, "validate-config", str(bad))
    assert code == 3 and "severity must be one of" in err


def test_carve_command_lists_and_writes(capsys, synth_dir, tmp_path):
    img = synth_dir / "unallocated" / "unallocated.dd"
    out = tmp_path / "carved"
    code, text, _ = run(capsys, "carve", str(img), "--out", str(out), "--dry-run")
    assert code == 0 and not out.exists() and "4 complete, 1 partial, 3 rejected" in text
    code, text, _ = run(capsys, "carve", str(img), "--out", str(out))
    assert code == 0 and len(list(out.iterdir())) == 5 and "zip" in text and "partial" in text
    code, _o, err = run(capsys, "carve", str(tmp_path / "nope.dd"), "--out", str(out))
    assert code == 3 and "image not found" in err


def test_verify_detects_changes_after_the_fact(capsys, synth_dir, tmp_path):
    case = tmp_path / "case"
    shutil.copytree(synth_dir, case)
    out = tmp_path / "out"
    assert run(capsys, "triage", "--case", str(case), "--out", str(out))[0] == 0
    manifest = out / "evidence_manifest.json"
    code, text, _ = run(capsys, "verify", "--manifest", str(manifest), "--base", str(case))
    assert code == 0 and text.startswith("OK: 38 files match")
    (case / "evidence" / syn.HOME / "Documents" / "todo.txt").write_text("edited later")
    (case / "unallocated" / "unallocated.dd").unlink()
    code, text, _ = run(capsys, "verify", "--manifest", str(manifest), "--base", str(case))
    assert code == 4 and "EVIDENCE CHANGED: 2 difference(s)" in text and "todo.txt: content" in text and "unallocated.dd: missing" in text
    code, _o, err = run(capsys, "verify", "--manifest", str(tmp_path / "nope.json"), "--base", str(case))
    assert code == 3 and "cannot read manifest" in err
    (tmp_path / "bad.json").write_text("[1,2]")
    assert run(capsys, "verify", "--manifest", str(tmp_path / "bad.json"), "--base", str(case))[0] == 3


def test_verify_custody(capsys, synth_dir, tmp_path):
    out = tmp_path / "out"
    run(capsys, "triage", "--case", str(synth_dir), "--out", str(out))
    log = out / "custody_log.json"
    code, text, _ = run(capsys, "verify-custody", str(log))
    assert code == 0 and text.startswith("OK: chain intact (9 entries)")
    doc = json.loads(log.read_text())
    doc["entries"][3]["detail"] = "edited"
    log.write_text(json.dumps(doc))
    code, text, _ = run(capsys, "verify-custody", str(log))
    assert code == 4 and text.startswith("BROKEN: entry 4")
    log.write_text(json.dumps(doc["entries"]))                       # a bare list is accepted too
    assert run(capsys, "verify-custody", str(log))[0] == 4
    assert run(capsys, "verify-custody", str(tmp_path / "missing.json"))[0] == 3


def test_generate_refuses_to_overwrite_foreign_folders(capsys, tmp_path):
    target = tmp_path / "mine"
    target.mkdir()
    (target / "important.txt").write_text("keep")
    code, _o, err = run(capsys, "generate", "--out", str(target))
    assert code == 3 and "refusing to overwrite" in err and (target / "important.txt").read_text() == "keep"
    fresh = tmp_path / "fresh"
    code, text, _ = run(capsys, "generate", "--out", str(fresh))
    assert code == 0 and (fresh / "README_SYNTHETIC.txt").is_file()
    assert run(capsys, "generate", "--out", str(fresh))[0] == 0          # regenerating a synthetic case is fine


def test_demo_end_to_end_in_temp_folders(capsys, tmp_path):
    code, text, _ = cli_demo = run(capsys, "demo", "--case-dir", str(tmp_path / "case"), "--reports-dir", str(tmp_path / "reports"),
                                    "--dashboard-json", str(tmp_path / "dash" / "case.json"))
    assert code == 0 and "ALL CHECKS PASSED" in text and "21/21 scenarios" in text
    ev = json.loads((tmp_path / "reports" / "evaluation.json").read_text())
    assert ev["passed"] and (tmp_path / "dash" / "case.json").is_file()
    assert len(list((tmp_path / "reports" / "carved").iterdir())) == 5
    assert run(capsys, "demo", "--case-dir", str(tmp_path / "case"), "--reports-dir", str(tmp_path / "reports"), "--dashboard-json", str(tmp_path / "dash" / "case.json"))[0] == 0


def test_python_dash_m_entry_point(synth_dir, tmp_path):
    import subprocess, sys
    proc = subprocess.run([sys.executable, "-m", "forensictriage", "--version"], capture_output=True, text=True, cwd=Path(cli.__file__).resolve().parent.parent)
    assert proc.returncode == 0 and proc.stdout.startswith("forensictriage 1.")
    proc = subprocess.run([sys.executable, "-m", "forensictriage"], capture_output=True, text=True, cwd=Path(cli.__file__).resolve().parent.parent)
    assert proc.returncode == 2          # argparse: a command is required


def test_verify_content_only_ignores_mtime_but_not_content(capsys, synth_dir, tmp_path):
    case = tmp_path / "case"
    shutil.copytree(synth_dir, case)
    out = tmp_path / "out"
    run(capsys, "triage", "--case", str(case), "--out", str(out))
    manifest = out / "evidence_manifest.json"
    todo = case / "evidence" / syn.HOME / "Documents" / "todo.txt"
    os.utime(todo, (1_000_000_000, 1_000_000_000))                                    # what a copy or checkout does
    code, text, _ = run(capsys, "verify", "--manifest", str(manifest), "--base", str(case))
    assert code == 4 and "todo.txt: metadata" in text
    code, text, _ = run(capsys, "verify", "--manifest", str(manifest), "--base", str(case), "--content-only")
    assert code == 0 and "by content and size" in text
    todo.write_text("tampered")
    code, text, _ = run(capsys, "verify", "--manifest", str(manifest), "--base", str(case), "--content-only")
    assert code == 4 and "todo.txt: content" in text
