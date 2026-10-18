import os

import pytest

from forensictriage import synthetic as syn
from forensictriage.fsmeta import FsMetaError, FsRecord, embedded_dates, norm_path, parse_mft_csv, stat_record
from forensictriage.timestomp import DAY_NS, assess
from forensictriage.timeutil import NS, parse_ts

T = parse_ts


def rec(si=(None,) * 4, fn=(None,) * 4, source="mft_export"):
    r = FsRecord("x", source=source)
    r.si = dict(zip(["created", "modified", "accessed", "mft_changed"], si))
    r.fn = dict(zip(["created", "modified", "accessed", "mft_changed"], fn))
    return r


NORMAL = (T("2025-01-01 10:00:00.1234567"), T("2025-02-01 10:00:00.7654321"), T("2025-02-02 10:00:00.1111111"), T("2025-02-01 10:00:00.7654321"))


def test_normal_file_has_no_indicators():
    r = assess(rec(NORMAL, (NORMAL[0],) * 4))
    assert r.verdict == "none" and r.score == 0 and r.indicators == []


def test_si_created_before_fn_is_the_classic_tell():
    fn = (T("2026-03-10 21:57:12.4418233"),) * 4
    r = assess(rec((T("2025-01-14 09:30:00.5"),) * 4, fn))
    ids = [i["id"] for i in r.indicators]
    assert "si_created_before_fn" in ids and r.verdict == "likely"


def test_fn_tolerance_ignores_tiny_differences():
    fn = (T("2025-01-01 10:00:01.5"),) * 4
    r = assess(rec((T("2025-01-01 10:00:00.1234567"), NORMAL[1], NORMAL[2], NORMAL[3]), fn), fn_tolerance_s=2)
    assert "si_created_before_fn" not in [i["id"] for i in r.indicators]
    r = assess(rec((T("2025-01-01 10:00:00.1234567"), NORMAL[1], NORMAL[2], NORMAL[3]), fn), fn_tolerance_s=0)
    assert "si_created_before_fn" in [i["id"] for i in r.indicators]


def test_modified_before_created_alone_is_weak_not_likely():
    r = assess(rec((T("2026-03-10 22:00:00.3"), T("2025-12-18 09:00:00.7"), T("2026-03-10 22:00:00.9"), NORMAL[3]), (T("2026-03-10 22:00:00.3"),) * 4))
    assert [i["id"] for i in r.indicators] == ["modified_before_created"] and r.verdict == "weak"


def test_zero_subsecond_weights_depend_on_fn_availability():
    whole = (T("2026-03-04 14:00:00"),) * 3 + (T("2026-03-04 14:00:00"),)
    with_fn = assess(rec(whole, (T("2026-03-04 14:00:00.7712"),) * 4))
    assert [i["id"] for i in with_fn.indicators] == ["zero_subsecond"] and with_fn.score == 2 and with_fn.verdict == "weak"
    no_fn = assess(rec(whole))
    assert [i["id"] for i in no_fn.indicators] == ["zero_subsecond_no_fn"] and no_fn.score == 1
    from_stat = assess(rec(whole, (T("2026-03-04 14:00:00.7712"),) * 4, source="stat"))
    assert [i["id"] for i in from_stat.indicators] == ["zero_subsecond_no_fn"]


def test_zero_subsecond_needs_two_timestamps():
    r = assess(rec((T("2026-03-04 14:00:00"), None, None, None)))
    assert r.indicators == []


def test_impossible_epoch_and_pre_1980_values():
    r = assess(rec((0, 0, 0, T("2026-03-06 10:12:20.77")), (T("2026-03-06 10:12:03.123"),) * 4))
    ids = [i["id"] for i in r.indicators]
    assert "impossible_value" in ids and "si_created_before_fn" in ids and r.verdict == "likely"
    r = assess(rec((T("1601-01-01 00:00:00"), NORMAL[1], NORMAL[2], NORMAL[3])))
    assert [i["id"] for i in r.indicators] == ["impossible_value"] and r.verdict == "likely"


def test_future_timestamps_need_an_acquisition_time():
    future = (NORMAL[0], NORMAL[1], T("2027-01-01 00:00:00.5"), NORMAL[3])
    assert assess(rec(future)).indicators == []
    r = assess(rec(future), acquired_ns=T("2026-03-16 08:30:00"))
    assert [i["id"] for i in r.indicators] == ["future_timestamp"]
    within_slack = (NORMAL[0], NORMAL[1], T("2026-03-16 20:00:00.5"), NORMAL[3])
    assert assess(rec(within_slack), acquired_ns=T("2026-03-16 08:30:00")).indicators == []


def test_embedded_document_date_later_than_file_modified():
    si = (NORMAL[0], T("2025-01-14 09:30:00.4"), NORMAL[2], NORMAL[3])
    emb = {"modified": T("2026-03-09 17:22:05")}
    assert "embedded_later_than_modified" in [i["id"] for i in assess(rec(si), emb).indicators]
    assert assess(rec(si), {"modified": T("2025-01-14 10:00:00")}).indicators == []     # inside the one-day slack
    assert assess(rec(si), {"created": T("2026-03-09 17:22:05")}).indicators == []
    assert assess(rec(si), {"modified": T("2026-03-09 17:22:05")}, embedded_slack_days=10000).indicators == []


def test_weights_and_threshold_are_configurable():
    fn = (T("2026-03-10 21:57:12.4418233"),) * 4
    r = assess(rec((T("2025-01-14 09:30:00.5"),) * 4, fn), weights={"si_created_before_fn": 1}, likely_score=2)
    assert r.score == 1 and r.verdict == "weak"
    r = assess(rec((T("2025-01-14 09:30:00.5"),) * 4, fn), weights={"si_created_before_fn": 1}, likely_score=1)
    assert r.verdict == "likely"


def test_synthetic_stomped_docx_scores_like_the_story(fresh_case):
    reports = parse_mft_csv((fresh_case / "artifacts" / "mft_export.csv").read_text())
    by = {r.path: r for r in reports}
    p = fresh_case / "evidence" / syn.STAGE / "Atlas_Roadmap.docx"
    r = by[f"{syn.STAGE}/Atlas_Roadmap.docx"]
    emb = embedded_dates(p, "docx")
    res = assess(r, emb, T("2026-03-16 08:30:00"))
    assert {i["id"] for i in res.indicators} == {"si_created_before_fn", "zero_subsecond", "embedded_later_than_modified"}
    assert res.score == 8 and res.verdict == "likely"


# ---------------------------------------------------------------- metadata CSV
def test_norm_path():
    assert norm_path("C:\\Users\\Bob\\a.txt") == "Users/Bob/a.txt"
    assert norm_path(".\\Users\\a.txt") == "Users/a.txt"
    assert norm_path("/x/y/") == "x/y"
    assert norm_path("  ") == ""


def test_mft_csv_basic_columns_and_comment_banner():
    text = ("# SYNTHETIC\npath,in_use,size,si_created,si_modified,si_accessed,si_mft_changed,fn_created\n"
            "Users/a/x.txt,true,12,2026-01-01 10:00:00.1,2026-01-02 10:00:00.2,2026-01-03,2026-01-02 10:00:00.2,2026-01-01 10:00:00.1\n"
            "Users/a/gone.txt,false,5,2026-01-01,2026-01-01,,,\n")
    rows = parse_mft_csv(text)
    assert [r.path for r in rows] == ["Users/a/x.txt", "Users/a/gone.txt"]
    assert rows[0].in_use and rows[0].size == 12 and rows[0].fn["created"] == T("2026-01-01 10:00:00.1") and rows[0].has_fn
    assert not rows[1].in_use and not rows[1].has_fn and rows[1].si["accessed"] is None


def test_mft_csv_mftecmd_style_columns():
    text = ("ParentPath,FileName,InUse,FileSize,Created0x10,LastModified0x10,LastRecordChange0x10,LastAccess0x10,Created0x30,LastModified0x30\n"
            ".\\Users\\bob,notes.txt,True,10,2026-02-01 08:00:00.1234567,2026-02-02 08:00:00.1234567,2026-02-02 08:00:00,2026-02-03 08:00:00,2026-02-01 08:00:00.1234567,2026-02-01 08:00:00.1234567\n")
    r = parse_mft_csv(text)[0]
    assert r.path == "Users/bob/notes.txt" and r.in_use and r.size == 10
    assert r.si["created"] == T("2026-02-01 08:00:00.1234567") and r.fn["modified"] is not None and r.si["mft_changed"] == T("2026-02-02 08:00:00")


@pytest.mark.parametrize("text", ["", "a,b\n1,2\n", "path,size\nx,1\n", "path,in_use\nx,1\n"])
def test_mft_csv_errors(text):
    with pytest.raises(FsMetaError):
        parse_mft_csv(text)


def test_mft_csv_skips_blank_paths_and_bad_sizes():
    rows = parse_mft_csv("path,size,si_created,si_modified\n,5,2026-01-01,2026-01-01\nok.txt,abc,2026-01-01,2026-01-01\n")
    assert len(rows) == 1 and rows[0].size is None


def test_stat_record_fallback(tmp_path):
    p = tmp_path / "f.txt"
    p.write_bytes(b"hello")
    os.utime(p, ns=(1_700_000_000 * NS + 5, 1_600_000_000 * NS + 7))
    r = stat_record(p, "sub\\f.txt")
    assert r.source == "stat" and r.path == "sub/f.txt" and r.size == 5
    assert r.si["modified"] == 1_600_000_000 * NS + 7 and r.si["accessed"] == 1_700_000_000 * NS + 5
    assert not r.has_fn


# ---------------------------------------------------------------- embedded dates
def test_embedded_dates_docx_xlsx_pdf_and_failures(tmp_path):
    d = tmp_path / "a.docx"
    d.write_bytes(syn.docx_bytes("t", ["x"], "2025-08-19T09:14:22Z", "2026-03-09T17:22:05Z"))
    assert embedded_dates(d, "docx") == {"created": T("2025-08-19 09:14:22"), "modified": T("2026-03-09 17:22:05")}
    x = tmp_path / "a.xlsx"
    x.write_bytes(syn.xlsx_bytes("t", [["a"]], "2025-01-01T00:00:00Z", "2025-02-01T00:00:00Z"))
    assert embedded_dates(x, "xlsx")["modified"] == T("2025-02-01 00:00:00")
    p = tmp_path / "a.pdf"
    p.write_bytes(syn.pdf_bytes("t", ["x"], "20260309223000", "20260310221900"))
    assert embedded_dates(p, "pdf") == {"created": T("2026-03-09 22:30:00"), "modified": T("2026-03-10 22:19:00")}
    big = tmp_path / "big.pdf"
    big.write_bytes(b"%PDF-1.4\n" + b"x" * 100_000 + syn.pdf_bytes("t", ["x"], "20260101000000", "20260102000000"))
    assert embedded_dates(big, "pdf")["modified"] == T("2026-01-02 00:00:00")
    bad = tmp_path / "bad.docx"
    bad.write_bytes(b"not a zip")
    assert embedded_dates(bad, "docx") == {}
    nocore = tmp_path / "nocore.docx"
    nocore.write_bytes(syn.zip_bytes({"word/document.xml": b"<x/>"}))
    assert embedded_dates(nocore, "docx") == {}
    assert embedded_dates(p, "jpeg") == {}
    assert embedded_dates(tmp_path / "missing.pdf", "pdf") == {}
