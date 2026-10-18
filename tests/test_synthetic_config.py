import json
import re
import shutil
import sqlite3
from pathlib import Path

import pytest

from forensictriage import synthetic as syn
from forensictriage.config import ConfigError, DEFAULT_CONFIG_PATH, load_config, validate
from forensictriage.iocs import IPV4_RE, classify_ip

ROOT = Path(__file__).resolve().parent.parent


# ------------------------------------------------------------------ synthetic generator
def tree_bytes(d: Path):
    return {str(p.relative_to(d)): p.read_bytes() for p in sorted(d.rglob("*")) if p.is_file()}


def test_generator_is_deterministic_across_runs_and_folders(tmp_path):
    syn.generate(tmp_path / "a")
    syn.generate(tmp_path / "b")
    assert tree_bytes(tmp_path / "a") == tree_bytes(tmp_path / "b")


def test_seed_changes_the_data(tmp_path):
    syn.generate(tmp_path / "a", seed=1)
    syn.generate(tmp_path / "b", seed=2)
    assert tree_bytes(tmp_path / "a")["unallocated/unallocated.dd"] != tree_bytes(tmp_path / "b")["unallocated/unallocated.dd"]


def test_everything_is_labelled_synthetic(synth_dir):
    assert "SYNTHETIC" in (synth_dir / "README_SYNTHETIC.txt").read_text()
    case = json.loads((synth_dir / "case.json").read_text())
    assert case["synthetic"] is True and "SYNTHETIC" in case["title"]
    for rel in ("artifacts/mft_export.csv", "artifacts/registry_export.csv", "hashsets/known_bad.txt", "hashsets/known_good.txt"):
        assert (synth_dir / rel).read_text().startswith("#") and "SYNTHETIC" in (synth_dir / rel).read_text().splitlines()[0], rel
    assert json.loads((synth_dir / "artifacts" / "prefetch_export.json").read_text())["synthetic"] is True
    assert json.loads((synth_dir / "ground_truth.json").read_text())["synthetic"] is True
    for p in (synth_dir / "evidence").rglob("*.txt"):
        assert b"SYNTHETIC" in p.read_bytes(), p


def test_all_addresses_are_documentation_or_private_ranges(synth_dir):
    seen = set()
    for p in synth_dir.rglob("*"):
        if p.is_file() and p.name != "unallocated.dd" and p.name != "History":
            for m in IPV4_RE.finditer(p.read_bytes().decode("latin-1")):
                seen.add(m.group())
    for ip in seen:
        assert ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.", "10.", "192.168.", "127.", "0.0.0.0")) or classify_ip(ip) is None, ip
    assert "203.0.113.45" in seen


def test_domains_and_emails_are_fictional(synth_dir):
    text = ""
    for p in synth_dir.rglob("*"):
        if p.is_file() and p.suffix in (".txt", ".csv", ".json", ".ps1"):
            text += p.read_text(errors="replace")
    for dom in re.findall(r"@([A-Za-z0-9.\-]+)", text):
        assert dom.endswith(".example") or dom.endswith(".example\n"), dom


def test_the_known_bad_stand_in_cannot_run(synth_dir):
    data = (synth_dir / "evidence" / syn.HOME / "Downloads" / "invoice_template.pdf").read_bytes()
    assert data[:2] == b"MZ" and b"NOT EXECUTABLE" in data and b"PE\x00\x00" not in data and len(data) == 512


def test_planted_artifacts_exist(synth_dir):
    root = synth_dir / "evidence"
    assert (root / "$Recycle.Bin" / syn.SID / "$IK3P9QZ.zip").is_file()
    assert not (root / "$Recycle.Bin" / syn.SID / "$RK3P9QZ.zip").exists()           # content removed
    assert (root / "$Recycle.Bin" / syn.SID / "$R8XW2MA.docx").is_file()               # content still there
    renamed = (root / syn.PHOTOS / "holiday_photos_2025.jpg").read_bytes()
    assert renamed[:4] == b"PK\x03\x04"
    blob = (synth_dir / "unallocated" / "unallocated.dd").read_bytes()
    assert renamed in blob                                                              # the deleted original sits in unallocated space
    assert len(blob) % 512 == 0


def test_history_database_is_a_real_chrome_style_sqlite_file(synth_dir):
    p = synth_dir / "evidence" / syn.HOME / "AppData/Local/Google/Chrome/User Data/Default/History"
    assert p.read_bytes()[:16] == b"SQLite format 3\x00"
    assert p.read_bytes()[96:100] == (3045000).to_bytes(4, "big")
    con = sqlite3.connect(f"file:{p}?mode=ro&immutable=1", uri=True)
    assert {r[0] for r in con.execute("select name from sqlite_master where type='table'")} >= {"urls", "visits", "downloads", "keyword_search_terms"}
    assert con.execute("select count(*) from visits").fetchone()[0] == 14
    con.close()


def test_generator_refuses_foreign_folders_but_regenerates_its_own(tmp_path):
    d = tmp_path / "x"
    d.mkdir()
    (d / "mine.txt").write_text("keep me")
    with pytest.raises(FileExistsError):
        syn.generate(d)
    assert (d / "mine.txt").read_text() == "keep me"
    ok = tmp_path / "ok"
    syn.generate(ok)
    (ok / "evidence" / "stale.txt").write_text("stale")
    syn.generate(ok)
    assert not (ok / "evidence" / "stale.txt").exists()


def test_builders_produce_valid_formats(tmp_path):
    import io, struct, zipfile, zlib
    assert syn.jpeg_bytes("a")[:2] == b"\xff\xd8" and syn.jpeg_bytes("a")[-2:] == b"\xff\xd9" and syn.jpeg_bytes("a") != syn.jpeg_bytes("b")
    png = syn.png_bytes("x", 5, 3)
    assert png[:8] == b"\x89PNG\r\n\x1a\n" and png.endswith(b"IEND\xaeB`\x82")
    z = syn.zip_bytes({"a": b"1", "b": b"2"})
    with zipfile.ZipFile(io.BytesIO(z)) as zf:
        assert zf.testzip() is None and zf.namelist() == ["a", "b"] and all(i.compress_type == zipfile.ZIP_STORED for i in zf.infolist())
    pdf = syn.pdf_bytes("t", ["a", "b"], "20260101000000", "20260101000000", jpeg=syn.jpeg_bytes("j"))
    xref = int(re.search(rb"startxref\n(\d+)\n", pdf).group(1))
    assert pdf[xref:xref + 4] == b"xref"
    for m in re.finditer(rb"(\d{10}) 00000 n", pdf):
        assert pdf[int(m.group(1)):].lstrip(b"0123456789")[:6] == b" 0 obj"
    assert pdf.endswith(b"%%EOF\n")
    assert syn.hosts_file().startswith(b"# SYNTHETIC")


def test_ground_truth_references_only_rules_in_the_config(truth):
    ids = {r["id"] for r in load_config()["rules"]}
    assert {e["rule"] for e in truth["expected_findings"]} <= ids
    assert {m["rule"] for m in truth["must_not_flag"]} <= ids
    assert len(truth["expected_findings"]) == 21 and len(truth["must_not_flag"]) == 9


# ------------------------------------------------------------------ configuration
def test_default_config_is_valid_and_complete():
    cfg = load_config()
    assert validate({k: v for k, v in cfg.items() if k != "_rules_by_id"}) == []
    assert len(cfg["rules"]) == 15 and cfg["_rules_by_id"]["FT-003"]["mitre"] == ["T1070.006"]
    for r in cfg["rules"]:
        assert re.fullmatch(r"FT-\d{3}", r["id"]) and r["response"]
        assert all(t in cfg["mitre"] for t in r["mitre"])


def mutate(fn):
    cfg = json.loads(DEFAULT_CONFIG_PATH.read_text())
    fn(cfg)
    return validate(cfg)


@pytest.mark.parametrize("change,needle", [
    (lambda c: c["thresholds"].pop("staging_min_files"), "thresholds.staging_min_files"),
    (lambda c: c["thresholds"].update(staging_min_files=-1), "non-negative"),
    (lambda c: c["thresholds"].update(staging_min_files=True), "non-negative"),
    (lambda c: c["lists"].pop("archive_tools"), "lists.archive_tools is missing"),
    (lambda c: c["lists"].update(staging_dir_patterns=["(unclosed"]), "bad regex"),
    (lambda c: c["lists"]["search_patterns"].update(x=["[bad"]), "search_patterns.x"),
    (lambda c: c["rules"].append(dict(c["rules"][0])), "duplicate rule id"),
    (lambda c: c["rules"][0].update(severity="urgent"), "severity must be one of"),
    (lambda c: c["rules"][0].update(response=[]), "at least one response"),
    (lambda c: c["rules"][0].pop("title"), "missing 'title'"),
    (lambda c: c["rules"][0].update(mitre=["T9999"]), "T9999"),
])
def test_validation_catches_mistakes(change, needle):
    problems = mutate(change)
    assert any(needle in p for p in problems), problems


def test_validate_rejects_non_objects():
    assert validate([]) == ["configuration must be a JSON object"]


def test_load_config_errors(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.json")
    (tmp_path / "bad.json").write_text("{nope")
    with pytest.raises(ConfigError, match="invalid JSON"):
        load_config(tmp_path / "bad.json")
    (tmp_path / "wrong.json").write_text("{}")
    with pytest.raises(ConfigError):
        load_config(tmp_path / "wrong.json")


def test_changing_a_list_changes_the_result_without_code_changes(synth_dir, tmp_path):
    from forensictriage.triage import CaseInputs, run_triage
    cfg = json.loads(DEFAULT_CONFIG_PATH.read_text())
    cfg["lists"]["anti_forensic_tools"] = []
    cfg["lists"]["file_sharing_domains"] = []
    cfg["lists"]["webmail_domains"] = []
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(cfg))
    res = run_triage(CaseInputs.from_case_json(synth_dir / "case.json"), tmp_path / "out", p)
    rules = {f.rule for f in res.findings}
    assert "FT-009" not in rules and "FT-010" not in rules and "FT-008" in rules
