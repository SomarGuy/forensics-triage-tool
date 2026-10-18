import pytest

from forensictriage.timeutil import (NS, filetime_to_ns, format_ts, has_zero_subsecond, ns_to_filetime, ns_to_webkit,
                                     parse_ts, strip_comments, to_ms, webkit_to_ns)


def test_parse_and_format_round_trip_with_100ns_precision():
    ns = parse_ts("2026-03-10 21:57:12.4418233")
    assert ns % NS == 441_823_300
    assert format_ts(ns) == "2026-03-10 21:57:12.4418233"
    assert format_ts(ns, 0) == "2026-03-10 21:57:12"
    assert format_ts(ns, 3) == "2026-03-10 21:57:12.441"


@pytest.mark.parametrize("text", ["2026-03-10T21:57:12Z", "2026-03-10 21:57:12", "2026-03-10T21:57:12+00:00", "2026-03-10 21:57:12,000"])
def test_equivalent_spellings(text):
    assert parse_ts(text) == parse_ts("2026-03-10 21:57:12")


def test_timezone_offsets_are_applied():
    assert parse_ts("2026-03-10T17:57:12-04:00") == parse_ts("2026-03-10 21:57:12")
    assert parse_ts("2026-03-10T23:57:12+0200") == parse_ts("2026-03-10 21:57:12")


def test_date_only_and_epoch_and_pre_epoch():
    assert parse_ts("1970-01-01") == 0
    assert parse_ts("1601-01-01 00:00:00") < 0
    assert format_ts(parse_ts("1601-01-01 00:00:00"), 0) == "1601-01-01 00:00:00"
    assert parse_ts("2026-03-10") == parse_ts("2026-03-10 00:00:00")


@pytest.mark.parametrize("bad", [None, "", "yesterday", "2026-13-01", "2026-02-30", "2026-03-10 25:00:00", "2026-03-10 10:61:00"])
def test_invalid_input_returns_none(bad):
    assert parse_ts(bad) is None


def test_format_none_is_empty():
    assert format_ts(None) == ""
    assert to_ms(None) is None
    assert to_ms(1_500_000_000) == 1500


def test_filetime_and_webkit_conversions():
    ns = parse_ts("2026-03-10 21:57:12.5")
    assert filetime_to_ns(ns_to_filetime(ns)) == ns
    assert webkit_to_ns(ns_to_webkit(ns)) == ns
    assert webkit_to_ns(0) is None
    assert filetime_to_ns(116444736000000000) == 0       # 1970-01-01 as a FILETIME


def test_zero_subsecond():
    assert has_zero_subsecond(parse_ts("2025-01-14 09:30:00"))
    assert not has_zero_subsecond(parse_ts("2025-01-14 09:30:00.0000001"))
    assert not has_zero_subsecond(None)


def test_strip_comments_and_bom():
    assert strip_comments("\ufeff# banner\n# more\na,b\n1,2\n") == "a,b\n1,2\n"
    assert strip_comments("a,b\n# not leading\n") == "a,b\n# not leading\n"
