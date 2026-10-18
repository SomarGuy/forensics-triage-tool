"""Timestamp helpers. Everything is carried as integer nanoseconds since the Unix epoch (UTC).

Plain ``datetime`` cannot hold the 100 ns precision of NTFS timestamps, and forensic work cares about
sub-second digits (a classic timestomping tell is a timestamp whose fraction is exactly zero).
"""
from __future__ import annotations

import re
from datetime import date
from typing import Optional

NS = 1_000_000_000
_DAYS_TO_EPOCH = 719163  # date(1970, 1, 1).toordinal()
FILETIME_EPOCH_OFFSET_S = 11_644_473_600  # seconds between 1601-01-01 and 1970-01-01
WEBKIT_EPOCH_OFFSET_S = FILETIME_EPOCH_OFFSET_S  # Chrome stores microseconds since 1601-01-01

_TS_RE = re.compile(
    r"^\s*(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?)?\s*(Z|[+-]\d{2}:?\d{2})?\s*$"
)


def parse_ts(value) -> Optional[int]:
    """Parse an ISO-8601 style string (up to 9 fractional digits, optional Z / +hh:mm) into epoch ns.

    Returns None for empty or unparseable input. Naive timestamps are taken as UTC.
    """
    if value is None:
        return None
    m = _TS_RE.match(str(value))
    if not m:
        return None
    y, mo, d, hh, mm, ss, frac, tz = m.groups()
    try:
        days = date(int(y), int(mo), int(d)).toordinal() - _DAYS_TO_EPOCH
    except ValueError:
        return None
    hh, mm, ss = int(hh or 0), int(mm or 0), int(ss or 0)
    if hh > 23 or mm > 59 or ss > 60:
        return None
    total = days * 86400 + hh * 3600 + mm * 60 + ss
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        total -= sign * (int(digits[:2]) * 3600 + int(digits[2:]) * 60)
    nanos = int((frac or "0").ljust(9, "0"))
    return total * NS + nanos


def format_ts(ns: Optional[int], digits: int = 7) -> str:
    """Format epoch ns as ``YYYY-MM-DD HH:MM:SS.fffffff`` (UTC). ``digits`` = 0..9 fractional digits."""
    if ns is None:
        return ""
    secs, nanos = divmod(ns, NS)
    days, rem = divmod(secs, 86400)
    d = date.fromordinal(days + _DAYS_TO_EPOCH)
    hh, rem = divmod(rem, 3600)
    mm, ss = divmod(rem, 60)
    out = f"{d.isoformat()} {hh:02d}:{mm:02d}:{ss:02d}"
    if digits > 0:
        out += "." + f"{nanos:09d}"[:digits]
    return out


def to_ms(ns: Optional[int]) -> Optional[int]:
    return None if ns is None else ns // 1_000_000


def filetime_to_ns(ft: int) -> int:
    """Windows FILETIME (100 ns ticks since 1601-01-01) to epoch ns."""
    return ft * 100 - FILETIME_EPOCH_OFFSET_S * NS


def webkit_to_ns(us: int) -> Optional[int]:
    """Chrome/WebKit timestamp (microseconds since 1601-01-01) to epoch ns. 0 means 'never'."""
    if not us:
        return None
    return us * 1000 - WEBKIT_EPOCH_OFFSET_S * NS


def ns_to_webkit(ns: int) -> int:
    return (ns + WEBKIT_EPOCH_OFFSET_S * NS) // 1000


def ns_to_filetime(ns: int) -> int:
    return (ns + FILETIME_EPOCH_OFFSET_S * NS) // 100


def has_zero_subsecond(ns: Optional[int]) -> bool:
    """True when the sub-second part (at NTFS 100 ns resolution) is exactly zero."""
    return ns is not None and (ns % NS) // 100 == 0


def strip_comments(text: str) -> str:
    """Drop a UTF-8 BOM and any leading ``#`` comment lines (used by the synthetic data's SYNTHETIC banner)."""
    text = text.lstrip("\ufeff")
    lines = text.splitlines(keepends=True)
    i = 0
    while i < len(lines) and lines[i].lstrip().startswith("#"):
        i += 1
    return "".join(lines[i:])
