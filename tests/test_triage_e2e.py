import copy
import json
import os
import shutil
from pathlib import Path

import pytest

from forensictriage import synthetic as syn
from forensictriage import triage as triage_mod
from forensictriage.custody import verify_chain
from forensictriage.evaluate import evaluate, format_evaluation
from forensictriage.hashing import hash_bytes
from forensictriage.report import build_report, md, render_markdown
from forensictriage.triage import CaseInputs, TriageError, run_triage
from forensictriage.timeutil import parse_ts


def fingerprint(root: Path):
    out = {}
    for dp, dn, fn in os.walk(root):
        for n in fn:
            p = Path(dp) / n
            st = p.stat()
            out[str(p.relative_to(root))] = (p.read_bytes(), st.st_mtime_ns, st.st_mode, st.st_size)
        for n in dn:
            out[str(Path(dp, n).relative_to(root)) + "/"] = None
    return out


def test_whole_run_leaves_every_evidence_file_and_folder_untouched(fresh_case, tmp_path):
    before = fingerprint(fresh_case)
    res = run_triage(CaseInputs.from_case_json(fresh_case / "case.json"), tmp_path / "out")
    assert fingerprint(fresh_case) == before
    assert res.integrity_ok and res.differences == []


def test_report_structure_and_numbers(report):
    for key in ("meta", "summary", "integrity", "window", "findings", "narrative", "files", "timeline", "iocs", "carved", "deleted", "browser", "artifacts", "mitre", "rules", "notes"):
        assert key in report
    s = report["summary"]
    assert s["files"] == len(report["files"]) == 32 and s["findings"] == len(report["findings"]) == 20
    assert sum(s["by_severity"].values()) == s["findings"]
    assert s["timeline_events"] == len(report["timeline"])
    assert s["integrity_ok"] is True and report["meta"]["synthetic"] is True
    assert "SYNTHETIC DATA" in report["meta"]["notice"]
    assert report["window"]["start"].startswith("2026-03-0")
    json.dumps(report)                                         # fully serialisable


def test_every_file_is_hashed_with_three_algorithms(case_result, synth_dir):
    for f in case_result.analysis.files:
        data = (synth_dir / "evidence" / f.path).read_bytes()
        d = hash_bytes(data)
        assert (f.md5, f.sha1, f.sha256, f.size) == (d.md5, d.sha1, d.sha256, d.size), f.path


def test_known_bad_and_known_good_are_applied(report):
    by = {f["path"].rsplit("/", 1)[-1]: f for f in report["files"]}
    assert by["invoice_template.pdf"]["hash_status"] == "known_bad" and "ExfilHelper" in by["invoice_template.pdf"]["hash_label"]
    for name in ("hosts", "corp_logo.png", "desktop.ini", "License.txt"):
        assert by[name]["hash_status"] == "known_good"
    assert by["corp_logo.png"]["suppressed"] == ["signature_mismatch"] and by["corp_logo.png"]["mismatch"] is not None
    assert "signature_mismatch" not in by["corp_logo.png"]["flags"]


def test_file_flags_match_the_story(report):
    by = {f["path"].rsplit("/", 1)[-1]: f for f in report["files"]}
    assert by["holiday_photos_2025.jpg"]["detected_type"] == "zip" and "signature_mismatch" in by["holiday_photos_2025.jpg"]["flags"]
    assert by["Atlas_Roadmap.docx"]["detected_type"] == "docx"
    assert "timestomp_likely" in next(f for f in report["files"] if f["path"].endswith("stage/Atlas_Roadmap.docx"))["flags"]
    assert "timestomp_likely" not in next(f for f in report["files"] if f["path"].endswith("Atlas/Atlas_Roadmap.docx"))["flags"]
    assert by["invoice_template.pdf"]["detected_type"] == "mz"
    assert by["History"]["detected_type"] == "sqlite" and "browser_history" in by["History"]["flags"]
    assert by["$IK3P9QZ.zip"]["detected_type"] == "recycle_i" and by["$IK3P9QZ.zip"]["mismatch"] is None


def test_timeline_has_all_sources_sorted_and_the_original_fn_time(report):
    tl = report["timeline"]
    assert [e["ms"] for e in tl] == sorted(e["ms"] for e in tl)
    assert {e["source"] for e in tl} >= {"FILESYSTEM", "NTFS $FN", "BROWSER", "PREFETCH", "REGISTRY", "RECYCLE BIN", "MFT", "DOCUMENT"}
    fn = [e for e in tl if e["source"] == "NTFS $FN"]
    assert len(fn) == 2 and any("2026-03-10 21:57:12" in e["time"] for e in fn)         # the real creation time of the stomped copy
    assert any(e["anomalous"] and e["time"].startswith("1970-01-01") for e in tl)
    macb = [e for e in tl if e["source"] == "FILESYSTEM" and e["macb"] != "MACB"]
    assert macb and all(len(e["macb"]) == 4 for e in tl if e["macb"])
    assert any(e["macb"] == "M..." or e["macb"] == "M.C." for e in tl) or any(set(e["macb"]) - set(".") for e in macb)


def test_findings_carry_severity_mitre_and_response(report):
    for f in report["findings"]:
        assert f["id"].startswith("FND-") and f["severity"] in ("critical", "high", "medium", "low")
        assert f["response"] and f["summary"] and f["title"]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    assert [order[f["severity"]] for f in report["findings"]] == sorted(order[f["severity"]] for f in report["findings"])
    ids = {t["id"] for t in report["mitre"]}
    assert {"T1036.008", "T1070.006", "T1052.001", "T1560.001", "T1070.004", "T1567.002", "T1074.001"} <= ids
    usb = next(f for f in report["findings"] if f["rule"] == "FT-007")
    assert usb["severity"] == "high" and any("coincides" in e for e in usb["evidence"]) and any("recent document" in e for e in usb["evidence"])
    assert [n["ms"] for n in report["narrative"]] == sorted(n["ms"] for n in report["narrative"])


def test_old_usb_device_is_listed_but_not_flagged(report):
    assert len(report["artifacts"]["usb_devices"]) == 2
    assert not any("AA00112233" in json.dumps(f) for f in report["findings"])


def test_browser_section(report):
    b = report["browser"]
    assert b["sources"][0]["visits"] == 14
    assert {v["category"] for v in b["flagged_visits"]} == {"file_sharing", "webmail", "job_search"}
    assert len(b["flagged_searches"]) == 2 and b["downloads"][0]["target_path"].endswith("invoice_template.pdf")


def test_carved_files_are_written_outside_the_evidence_and_hashed(case_result, synth_dir):
    carved_dir = case_result.out_dir / "carved"
    names = sorted(p.name for p in carved_dir.iterdir())
    assert len(names) == 5 and all(n.startswith("carved_") for n in names)
    for c in case_result.analysis.carved:
        data = (carved_dir / c["name"]).read_bytes()
        assert hash_bytes(data).sha256 == c["sha256"] and len(data) == c["length"]
    assert not any(synth_dir in p.parents for p in carved_dir.iterdir())


def test_custody_log_and_manifest_files(case_result):
    out = case_result.out_dir
    doc = json.loads((out / "custody_log.json").read_text())
    assert doc["chain_ok"] is True and verify_chain(doc["entries"])[0]
    actions = [e["action"] for e in doc["entries"]]
    assert actions == ["CASE_OPENED", "HASH_BEFORE", "REFERENCE_LOADED", "ANALYSIS_ARTEFACTS", "ANALYSIS_CARVING", "ANALYSIS_IOCS", "HASH_AFTER", "VERIFY_OK", "REPORT_WRITTEN"]
    import hashlib
    assert doc["entries"][-1]["data"]["case_report_json_sha256"] == hashlib.sha256((out / "case_report.json").read_bytes()).hexdigest()
    man = json.loads((out / "evidence_manifest.json").read_text())
    assert man["files"] == 38 and len(man["digest_sha256"]) == 64
    assert any(e["kind"] == "raw" for e in man["entries"]) and any(e["kind"] == "export" for e in man["entries"]) and any(e["kind"] == "reference" for e in man["entries"])
    assert not any(os.path.isabs(e["rel"]) for e in man["entries"])
    before = next(e for e in doc["entries"] if e["action"] == "HASH_BEFORE")["data"]["manifest_sha256"]
    after = next(e for e in doc["entries"] if e["action"] == "HASH_AFTER")["data"]["manifest_sha256"]
    assert before == after == man["digest_sha256"]


def test_no_absolute_paths_leak_into_the_reports(case_result, synth_dir):
    text = (case_result.out_dir / "case_report.json").read_text() + (case_result.out_dir / "case_report.md").read_text()
    assert str(synth_dir) not in text and str(case_result.out_dir) not in text


def test_markdown_report_content(case_result):
    text = (case_result.out_dir / "case_report.md").read_text()
    assert text.startswith("# Forensic triage report: FT-2026-0417")
    for heading in ("## Evidence integrity and chain of custody", "## Findings", "## Case timeline", "## Flagged files", "## Carved files", "## External indicators", "## Method notes"):
        assert heading in text
    assert "SYNTHETIC DATA" in text and "VERIFIED UNCHANGED" in text and "FND-001 [CRITICAL]" in text and "T1070.006" in text
    assert "203.0.113.45" in text


def test_markdown_escaping():
    assert md("a|b`c\nd\r") == "a\\|b'c d "
    rep = {"meta": {"notice": "n", "title": "", "examiner": "", "generated_at": "t", "tool": "x", "version": "1", "evidence_acquired_at": "", "evidence_root": "r", "raw_images": [], "case_id": "C", "description": ""},
           "summary": {"files": 0, "bytes": 0, "findings": 1, "by_severity": {"critical": 0, "high": 0, "medium": 1, "low": 0}},
           "integrity": {"ok": False, "method": "m", "before": {"files": 1, "bytes": 1, "manifest_sha256": "a"}, "after": {"files": 1, "bytes": 1, "manifest_sha256": "b"},
                         "differences": [{"label": "root/x`y", "change": "content", "detail": "d|e"}], "custody_chain_note": "n", "custody": []},
           "findings": [{"id": "FND-001", "severity": "medium", "title": "T`itle|x", "rule": "FT-1", "category": "c", "first_seen": "", "mitre": [], "summary": "s\nnext",
                         "evidence": ["```code fence```", "a | b"], "files": ["f`.txt"], "response": ["do it"]}],
           "narrative": [], "files": [], "carved": {"stats": [], "files": []}, "iocs": [], "notes": ["note`x"]}
    text = render_markdown(rep)
    assert "```" not in text and "CHANGED DURING ANALYSIS" in text and "1 difference(s)" in text
    assert "T'itle\\|x" in text and "a \\| b" in text


# ---------------------------------------------------------------- safety
def test_refuses_to_write_inside_the_evidence(fresh_case):
    inputs = CaseInputs.from_case_json(fresh_case / "case.json")
    with pytest.raises(TriageError, match="inside the evidence"):
        run_triage(inputs, fresh_case / "evidence" / "reports")
    with pytest.raises(TriageError, match="inside the evidence"):
        run_triage(inputs, fresh_case / "evidence")


def test_refuses_to_write_next_to_input_files(fresh_case):
    inputs = CaseInputs.from_case_json(fresh_case / "case.json")
    with pytest.raises(TriageError, match="holds an input file"):
        run_triage(inputs, fresh_case / "artifacts")
    with pytest.raises(TriageError, match="holds an input file"):
        run_triage(inputs, fresh_case / "unallocated")


@pytest.mark.parametrize("attr", ["raw_images", "metadata", "prefetch", "registry", "known_bad", "known_good"])
def test_missing_inputs_are_reported_clearly(fresh_case, tmp_path, attr):
    inputs = CaseInputs.from_case_json(fresh_case / "case.json")
    setattr(inputs, attr, [tmp_path / "nope"] if attr == "raw_images" else tmp_path / "nope")
    with pytest.raises(TriageError, match="not found"):
        run_triage(inputs, tmp_path / "out")


def test_root_must_be_a_directory(tmp_path):
    f = tmp_path / "file"
    f.write_text("x")
    with pytest.raises(TriageError, match="not a directory"):
        run_triage(CaseInputs("X", f), tmp_path / "out")


def test_tampering_during_the_run_is_detected(fresh_case, tmp_path, monkeypatch):
    victim = fresh_case / "evidence" / syn.HOME / "Documents" / "todo.txt"
    orig = triage_mod.detect_type
    state = {"done": False}

    def evil(path, head=None):
        if not state["done"]:
            state["done"] = True
            victim.write_bytes(victim.read_bytes() + b"tampered")
            (fresh_case / "evidence" / "planted.txt").write_text("added during analysis")
            (fresh_case / "evidence" / syn.HOME / "Documents" / "notes_to_self.txt").unlink()
        return orig(path, head)
    monkeypatch.setattr(triage_mod, "detect_type", evil)
    res = run_triage(CaseInputs.from_case_json(fresh_case / "case.json"), tmp_path / "out")
    assert not res.integrity_ok
    changes = {d["label"]: d["change"] for d in res.differences}
    assert changes["root/Users/jwhitfield/Documents/todo.txt"] == "content"
    assert changes["root/planted.txt"] == "added"
    assert changes["root/Users/jwhitfield/Documents/notes_to_self.txt"] == "missing"
    f0 = res.findings[0]
    assert f0.rule == "FT-900" and f0.severity == "critical" and f0.id == "FND-001"
    rep = build_report(res)
    assert rep["integrity"]["ok"] is False and rep["summary"]["integrity_ok"] is False
    assert "VERIFY_FAILED" in [e["action"] for e in res.custody.entries]
    assert "CHANGED DURING ANALYSIS" in (tmp_path / "out" / "case_report.md").read_text()


# ---------------------------------------------------------------- behaviour on other inputs
def adhoc(tmp_path, files, **kw):
    root = tmp_path / "ev"
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    inputs = CaseInputs("ADHOC", root, **kw)
    return inputs, tmp_path / "out"


def test_plain_folder_uses_stat_timestamps_and_still_works(tmp_path):
    inputs, out = adhoc(tmp_path, {"a.txt": b"hello 203.0.113.9", "b.jpg": syn.zip_bytes({"x": b"y"}), "sub/c.pdf": syn.pdf_bytes("t", ["x"], "20260101000000", "20260101000000")})
    res = run_triage(inputs, out)
    rep = build_report(res)
    assert rep["summary"]["files"] == 3 and all(f["metadata_source"] == "stat" for f in rep["files"])
    assert any(f["rule"] == "FT-002" and "b.jpg" in f["title"] for f in rep["findings"])
    assert any(f["rule"] == "FT-013" for f in rep["findings"])
    assert rep["timeline"] and rep["artifacts"]["usb_devices"] == [] and rep["carved"]["files"] == []
    assert rep["meta"]["synthetic"] is False and "SYNTHETIC" not in rep["meta"]["notice"]


def test_empty_folder_and_empty_raw_image(tmp_path):
    root = tmp_path / "ev"
    root.mkdir()
    raw = tmp_path / "raw" / "empty.dd"
    raw.parent.mkdir()
    raw.write_bytes(b"")
    res = run_triage(CaseInputs("E", root, raw_images=[raw]), tmp_path / "out")
    rep = build_report(res)
    assert rep["summary"]["files"] == 0 and rep["findings"] == [] and rep["carved"]["stats"][0]["bytes_scanned"] == 0
    assert rep["integrity"]["ok"]


def test_known_good_hash_suppresses_mismatch_and_timestomp_flags(tmp_path):
    stub = syn.mz_stub()
    inputs, out = adhoc(tmp_path, {"tool.pdf": stub})
    kg = tmp_path / "good.txt"
    kg.write_text(f"{hash_bytes(stub).sha256}  our standard tool\n")
    inputs.known_good = kg
    res = run_triage(inputs, out)
    f = res.analysis.files[0]
    assert f.hash_status == "known_good" and "signature_mismatch" not in f.flags and f.suppressed == ["signature_mismatch"]
    assert not [x for x in res.findings if x.rule == "FT-002"]
    kb = tmp_path / "bad.txt"                                   # known-bad overrides known-good
    kb.write_text(f"{hash_bytes(stub).sha256}  bad\n")
    inputs.known_bad = kb
    res = run_triage(inputs, tmp_path / "out2")
    assert res.analysis.files[0].hash_status == "known_bad" and res.findings[0].rule == "FT-001"


def test_broken_exports_become_notes_not_crashes(fresh_case, tmp_path):
    (fresh_case / "artifacts" / "prefetch_export.json").write_text("{not json")
    (fresh_case / "artifacts" / "registry_export.csv").write_text("a,b\n1,2\n")
    (fresh_case / "artifacts" / "mft_export.csv").write_text("x,y\n1,2\n")
    (fresh_case / "hashsets" / "known_bad.txt").write_text("garbage line\n")
    res = run_triage(CaseInputs.from_case_json(fresh_case / "case.json"), tmp_path / "out")
    notes = " | ".join(res.analysis.notes)
    assert "prefetch export could not be parsed" in notes and "registry export could not be parsed" in notes
    assert "falling back to os.stat" in notes and "not valid hashes" in notes
    assert res.integrity_ok and res.analysis.prefetch == [] and res.analysis.usb == []
    assert all(f.fs.source == "stat" for f in res.analysis.files)
    assert "Processing notes" in (tmp_path / "out" / "case_report.md").read_text()


def test_unparseable_sqlite_is_noted(tmp_path):
    import sqlite3
    inputs, out = adhoc(tmp_path, {})
    inputs.root.mkdir(parents=True, exist_ok=True)
    db = inputs.root / "other.sqlite"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE t(a)")
    con.commit()
    con.close()
    res = run_triage(inputs, out)
    assert any("not parsed as browser history" in n for n in res.analysis.notes)


def test_malformed_and_v1_recycle_records(tmp_path):
    from forensictriage.recyclebin import build_i_file
    rb = "$Recycle.Bin/S-1-5-21-1/"
    inputs, out = adhoc(tmp_path, {rb + "$IAAAAAA.txt": b"short", rb + "$IBBBBBB.txt": build_i_file("C:\\x\\old.txt", 7, parse_ts("2026-03-01 10:00:00"), 1)})
    res = run_triage(inputs, out)
    recs = {r["i_path"].rsplit("/", 1)[-1]: r for r in res.analysis.recycle}
    assert recs["$IAAAAAA.txt"]["malformed"] and recs["$IBBBBBB.txt"]["version"] == 1 and recs["$IBBBBBB.txt"]["original_path"] == "C:\\x\\old.txt"
    assert any("malformed $I file" in n for n in res.analysis.notes)
    assert [f.rule for f in res.findings if f.rule == "FT-006"] == ["FT-006"]            # the valid record has no $R, so it is reported


def test_symlinks_in_evidence_are_skipped_not_followed(tmp_path):
    inputs, out = adhoc(tmp_path, {"a.txt": b"x"})
    outside = tmp_path / "secret.txt"
    outside.write_text("203.0.113.99")
    try:
        os.symlink(outside, inputs.root / "link.txt")
    except OSError:
        pytest.skip("symlinks not available")
    res = run_triage(inputs, out)
    assert [f.path for f in res.analysis.files] == ["a.txt"]
    assert any("symlink" in n for n in res.analysis.notes)
    assert not any(i.value == "203.0.113.99" for i in res.analysis.iocs)
    assert res.before.skipped


def test_scan_cap_limits_how_much_of_a_file_is_read_for_indicators(tmp_path):
    cfg = json.loads(Path(triage_mod.load_config.__globals__["DEFAULT_CONFIG_PATH"]).read_text())
    cfg["thresholds"]["max_scan_bytes"] = 64
    cpath = tmp_path / "cfg.json"
    cpath.write_text(json.dumps(cfg))
    inputs, out = adhoc(tmp_path, {"big.txt": b"A" * 200 + b" 203.0.113.9 ", "small.txt": b"203.0.113.8 "})
    res = run_triage(inputs, out, cpath)
    vals = {i.value for i in res.analysis.iocs}
    assert "203.0.113.8" in vals and "203.0.113.9" not in vals


def test_acquisition_time_enables_future_timestamp_check(tmp_path):
    inputs, out = adhoc(tmp_path, {"a.txt": b"x"})
    os.utime(inputs.root / "a.txt", ns=(parse_ts("2030-01-01 00:00:00.123456789"), parse_ts("2030-01-01 00:00:00.987654321")))
    quiet = run_triage(inputs, out)
    assert quiet.analysis.files[0].timestomp.verdict == "none"
    inputs.acquired_at = parse_ts("2026-03-16 08:30:00")
    res = run_triage(inputs, tmp_path / "out2")
    assert any(i["id"] == "future_timestamp" for i in res.analysis.files[0].timestomp.indicators)


def test_results_are_deterministic(fresh_case, tmp_path):
    a = build_report(run_triage(CaseInputs.from_case_json(fresh_case / "case.json"), tmp_path / "o1"))
    b = build_report(run_triage(CaseInputs.from_case_json(fresh_case / "case.json"), tmp_path / "o2"))
    for key in ("summary", "findings", "files", "timeline", "iocs", "carved", "mitre", "narrative"):
        assert a[key] == b[key], key


def test_case_json_errors(tmp_path):
    with pytest.raises(TriageError, match="cannot read"):
        CaseInputs.from_case_json(tmp_path / "missing.json")
    (tmp_path / "bad.json").write_text("{nope")
    with pytest.raises(TriageError, match="cannot read"):
        CaseInputs.from_case_json(tmp_path / "bad.json")
    (tmp_path / "partial.json").write_text('{"case_id": "x"}')
    with pytest.raises(TriageError, match="evidence_root"):
        CaseInputs.from_case_json(tmp_path / "partial.json")


# ---------------------------------------------------------------- evaluation against ground truth
def test_evaluation_passes_on_the_synthetic_case(report, truth):
    ev = evaluate(report, truth)
    assert ev["passed"], format_evaluation(ev)
    assert ev["scenarios_passed"] == ev["scenarios_total"] == 21 and ev["must_not_passed"] == 9 and ev["unexpected_findings"] == []
    text = format_evaluation(ev)
    assert "ALL CHECKS PASSED" in text and "SYNTHETIC" in text


def test_evaluation_fails_when_a_planted_finding_is_missing(report, truth):
    rep = copy.deepcopy(report)
    rep["findings"] = [f for f in rep["findings"] if f["rule"] != "FT-003"]
    ev = evaluate(rep, truth)
    assert not ev["passed"] and any(s["id"] == "GT-05" and not s["passed"] for s in ev["scenarios"])
    assert "FAILED" in format_evaluation(ev) and "no matching finding" in format_evaluation(ev)


def test_evaluation_fails_on_an_unexpected_or_downgraded_finding(report, truth):
    rep = copy.deepcopy(report)
    extra = dict(rep["findings"][0], id="FND-099", rule="FT-003", title="Timestamps consistent with timestomping: Q4_report_copy.xlsx", files=["x/Q4_report_copy.xlsx"], evidence=[], summary="s")
    rep["findings"].append(extra)
    ev = evaluate(rep, truth)
    assert not ev["passed"] and any(not m["passed"] and m["path"] == "Q4_report_copy.xlsx" for m in ev["must_not_flag"])
    rep = copy.deepcopy(report)
    for f in rep["findings"]:
        if f["rule"] == "FT-009":
            f["severity"] = "low"
    ev = evaluate(rep, truth)
    assert any("below high" in s["detail"] for s in ev["scenarios"])
    rep = copy.deepcopy(report)
    rep["findings"].append(dict(rep["findings"][0], id="FND-098", rule="FT-014", title="something else entirely", files=[], evidence=[], summary="nothing"))
    assert evaluate(rep, truth)["unexpected_findings"]


def test_evaluation_checks_carving_iocs_counts_usb_and_integrity(report, truth):
    rep = copy.deepcopy(report)
    rep["carved"]["stats"][0]["rejected"] = 0
    rep["iocs"] = [i for i in rep["iocs"] if i["value"] != "203.0.113.45"] + [dict(report["iocs"][0], value="http://schemas.openxmlformats.org/x")]
    rep["summary"]["files"] = 1
    rep["artifacts"]["usb_devices"] = rep["artifacts"]["usb_devices"][:1]
    rep["integrity"]["ok"] = False
    ev = evaluate(rep, truth)
    assert not ev["passed"]
    assert any(not c["passed"] for c in ev["carving"]) and any(not i["passed"] for i in ev["iocs"]) and ev["noise_iocs"] and any(not c["passed"] for c in ev["counts"])
    assert ev["usb_serials"] != sorted(truth["expected_usb_serials"]) and ev["integrity_ok"] is False


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() == 0, reason="needs a non-root user to make a file unreadable")
def test_unreadable_file_is_noted_and_the_rest_is_analysed(tmp_path):
    inputs, out = adhoc(tmp_path, {"ok.txt": b"fine", "locked.txt": b"secret"})
    locked = inputs.root / "locked.txt"
    locked.chmod(0)
    try:
        res = run_triage(inputs, out)
    finally:
        locked.chmod(0o644)
    assert [f.path for f in res.analysis.files] == ["ok.txt"]
    assert any("locked.txt" in n and "could not be read" in n for n in res.analysis.notes)
    assert any("unreadable" in s["reason"] for s in res.before.skipped)
