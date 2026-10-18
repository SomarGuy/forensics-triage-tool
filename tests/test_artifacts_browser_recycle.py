import json
import sqlite3
import struct

import pytest

from forensictriage import synthetic as syn
from forensictriage.artifacts import ArtifactError, parse_prefetch_json, parse_registry_csv, recent_docs, usb_devices
from forensictriage.browser import BrowserParseError, classify_visits, host_of, match_searches, parse_history
from forensictriage.recyclebin import RecycleParseError, build_i_file, parse_i_file
from forensictriage.timeutil import parse_ts

T = parse_ts


# ---------------------------------------------------------------- recycle bin
@pytest.mark.parametrize("version", [1, 2])
def test_recycle_round_trip(version):
    path = "C:\\Users\\jwhitfield\\AppData\\Local\\Temp\\stage\\proj_backup.zip"
    when = T("2026-03-10 22:20:31.6021111")
    r = parse_i_file(build_i_file(path, 123456, when, version))
    assert (r.version, r.original_size, r.original_path) == (version, 123456, path)
    assert abs(r.deleted_ns - when) < 100              # FILETIME resolution is 100 ns


def test_recycle_v1_is_fixed_size_544():
    assert len(build_i_file("C:\\a.txt", 1, 0, 1)) == 544


def test_recycle_unicode_path():
    r = parse_i_file(build_i_file("C:\\Users\\Zo\u00eb\\r\u00e9sum\u00e9.docx", 9, T("2026-01-01")))
    assert r.original_path.endswith("r\u00e9sum\u00e9.docx")


@pytest.mark.parametrize("data", [b"", b"\x02" * 10, struct.pack("<qqq", 3, 1, 0) + b"\x00" * 40,
                                  struct.pack("<qqq", 2, 1, 0),                                   # no length field
                                  struct.pack("<qqq", 2, 1, 0) + struct.pack("<I", 0),            # zero chars
                                  struct.pack("<qqq", 2, 1, 0) + struct.pack("<I", 500) + b"ab",  # length larger than data
                                  struct.pack("<qqq", 2, -5, 0) + struct.pack("<I", 2) + b"a\x00\x00\x00",
                                  struct.pack("<qqq", 1, 1, 0) + b"\x00"])
def test_recycle_malformed(data):
    with pytest.raises(RecycleParseError):
        parse_i_file(data)


# ---------------------------------------------------------------- prefetch
def test_prefetch_list_and_dict_forms_and_aliases():
    rows = [{"Executable": "7zg.exe", "RunCount": 2, "LastRun": ["2026-03-10 22:05:12", "2026-03-10 21:58:30"], "Path": "C:\\x\\7zg.exe"},
            {"name": "notepad.exe", "last_run_times": "2026-01-01 10:00:00"}, {"nothing": 1}, "junk"]
    for doc in (rows, {"entries": rows}):
        out = parse_prefetch_json(json.dumps(doc))
        assert [p.executable for p in out] == ["7ZG.EXE", "NOTEPAD.EXE"]
        assert out[0].run_count == 2 and out[0].last_runs_ns == sorted(out[0].last_runs_ns) and out[0].path == "C:\\x\\7zg.exe"
        assert out[1].run_count == 1


def test_prefetch_bad_run_count_falls_back_to_number_of_times():
    out = parse_prefetch_json(json.dumps([{"executable": "a.exe", "run_count": "many", "last_run_times": ["2026-01-01 00:00:00", "bad"]}]))
    assert out[0].run_count == 1


@pytest.mark.parametrize("text", ["{oops", '"string"', '{"entries": 5}'])
def test_prefetch_errors(text):
    with pytest.raises(ArtifactError):
        parse_prefetch_json(text)


# ---------------------------------------------------------------- registry
def test_registry_usb_devices_and_recent_docs(synth_dir):
    vals = parse_registry_csv((synth_dir / "artifacts" / "registry_export.csv").read_text())
    devs = usb_devices(vals)
    assert [d.serial for d in devs] == ["0701A2B3C4D5E6F7&0", "AA00112233&0"]
    d = devs[0]
    assert (d.vendor, d.product, d.drive_letter) == ("NovaTech", "FlashDrive 64G", "E:")
    assert d.friendly_name.startswith("NovaTech") and d.first_install_ns < d.last_arrival_ns < d.last_removal_ns
    assert devs[1].drive_letter == ""
    docs = recent_docs(vals)
    assert {v.value_name for v in docs} == {"holiday_photos_2025.jpg", "Q1_Customer_Pricing.xlsx", "Meeting_Notes_Feb.docx"}


def test_registry_header_aliases_and_errors():
    text = "KeyPath,ValueName,Type,Data,LastWriteTime\nHKLM\\x,a,REG_SZ,b,2026-01-01 00:00:00\n"
    v = parse_registry_csv(text)[0]
    assert (v.key_path, v.value_name, v.value_type, v.value_data) == ("HKLM\\x", "a", "REG_SZ", "b") and v.last_write_ns
    minimal = parse_registry_csv("key_path,value_name\nA,b\n")[0]
    assert minimal.value_data == "" and minimal.last_write_ns is None
    with pytest.raises(ArtifactError):
        parse_registry_csv("")
    with pytest.raises(ArtifactError):
        parse_registry_csv("a,b\n1,2\n")


# ---------------------------------------------------------------- browser history
def test_parse_history_reads_visits_downloads_and_searches(synth_dir):
    p = synth_dir / "evidence" / syn.HOME / "AppData/Local/Google/Chrome/User Data/Default/History"
    b = parse_history(p)
    assert len(b.visits) == 14 and b.urls >= 10
    hosts = {v["host"] for v in b.visits}
    assert {"quickdrop-transfer.example", "mailbox-secure.example", "careerlink-jobs.example"} <= hosts
    assert [v["time_ns"] for v in b.visits] == sorted(v["time_ns"] for v in b.visits)
    assert b.downloads[0]["target_path"].endswith("invoice_template.pdf") and b.downloads[0]["host"] == "vendor-portal.example"
    assert {s["term"] for s in b.searches} >= {"how to change file modified date windows", "delete files permanently windows no recovery"}
    typed = [v for v in b.visits if v["transition"] == "typed"]
    assert typed


def test_parse_history_does_not_touch_the_evidence_or_create_sidecar_files(synth_dir):
    p = synth_dir / "evidence" / syn.HOME / "AppData/Local/Google/Chrome/User Data/Default/History"
    before = (p.read_bytes(), sorted(x.name for x in p.parent.iterdir()))
    parse_history(p)
    assert (p.read_bytes(), sorted(x.name for x in p.parent.iterdir())) == before


def test_classification_and_search_matching(synth_dir):
    p = synth_dir / "evidence" / syn.HOME / "AppData/Local/Google/Chrome/User Data/Default/History"
    b = parse_history(p)
    hits = classify_visits(b, {"file_sharing": ["quickdrop-transfer.example"], "webmail": ["mailbox-secure.example"]})
    assert {h["category"] for h in hits} == {"file_sharing", "webmail"} and len(hits) == 4
    s = match_searches(b, {"anti_forensics": ["delete.*permanent", "(change|edit).*(modified|timestamp)"]})
    assert len(s) == 2 and {x["category"] for x in s} == {"anti_forensics"}
    assert match_searches(b, {"x": ["^zzz$"]}) == []
    assert classify_visits(b, {}) == []


def test_parse_history_rejects_non_history_and_corrupt_files(tmp_path):
    other = tmp_path / "other.db"
    con = sqlite3.connect(other)
    con.execute("CREATE TABLE t(a)")
    con.commit()
    con.close()
    with pytest.raises(BrowserParseError, match="not a Chrome-style"):
        parse_history(other)
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"this is not sqlite at all" * 100)
    with pytest.raises(BrowserParseError):
        parse_history(junk)
    with pytest.raises(BrowserParseError):
        parse_history(tmp_path / "missing.db")


def test_history_without_optional_tables(tmp_path):
    p = tmp_path / "H"
    con = sqlite3.connect(p)
    con.execute("CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INT, typed_count INT, last_visit_time INT, hidden INT)")
    con.execute("CREATE TABLE visits(id INTEGER PRIMARY KEY, url INT, visit_time INT, from_visit INT, transition INT, segment_id INT, visit_duration INT)")
    con.execute("INSERT INTO urls VALUES(1,'https://a.example/x','A',1,0,13000000000000000,0)")
    con.execute("INSERT INTO visits VALUES(1,1,13000000000000000,0,805306368,0,0)")        # core transition 0 with qualifier bits set
    con.commit()
    con.close()
    b = parse_history(p)
    assert len(b.visits) == 1 and b.visits[0]["transition"] == "link"
    assert b.downloads == [] and b.searches == [] and len(b.notes) == 2


def test_host_of_bad_urls():
    assert host_of("https://User@Example.COM:8080/x") == "example.com"
    assert host_of("http://[::1") == ""
    assert host_of("not a url") == ""
