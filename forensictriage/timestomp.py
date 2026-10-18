"""Timestomping indicators.

No single indicator proves tampering: a file copied from another disk legitimately has a *modified*
time earlier than its *created* time, FAT-style volumes only store 2-second timestamps, and unzip tools
write whole-second times. So each indicator has a weight, and a file is only called "likely timestomped"
when the weights add up (default 3). Weak, single-indicator results are reported separately as
"weak anomalies" so they stay visible without crying wolf.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .fsmeta import FsRecord
from .timeutil import NS, format_ts, has_zero_subsecond, parse_ts

DAY_NS = 86400 * NS
YEAR_1980_NS = parse_ts("1980-01-01")

DEFAULT_WEIGHTS = {
    "si_created_before_fn": 3,
    "modified_before_created": 1,
    "zero_subsecond": 2,
    "zero_subsecond_no_fn": 1,
    "impossible_value": 3,
    "future_timestamp": 2,
    "embedded_later_than_modified": 3,
}


@dataclass
class TimestompResult:
    score: int = 0
    indicators: List[dict] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        return "none" if not self.indicators else ("likely" if self.score >= self._threshold else "weak")

    _threshold: int = 3


def assess(rec: FsRecord, embedded: Optional[Dict[str, int]] = None, acquired_ns: Optional[int] = None,
           weights: Optional[Dict[str, int]] = None, likely_score: int = 3, fn_tolerance_s: int = 2,
           embedded_slack_days: int = 1, future_slack_days: int = 1) -> TimestompResult:
    w = dict(DEFAULT_WEIGHTS)
    w.update(weights or {})
    res = TimestompResult(_threshold=likely_score)
    tol = fn_tolerance_s * NS

    def add(key: str, detail: str) -> None:
        res.indicators.append({"id": key, "weight": w[key], "detail": detail})
        res.score += w[key]

    si, fn = rec.si, rec.fn
    if si["created"] is not None and fn["created"] is not None and si["created"] < fn["created"] - tol:
        add("si_created_before_fn", f"$SI created {format_ts(si['created'])} is earlier than $FN created {format_ts(fn['created'])}; user-mode tools can set $SI but not $FN")
    if si["created"] is not None and si["modified"] is not None and si["modified"] < si["created"] - NS:
        add("modified_before_created", f"modified {format_ts(si['modified'])} is earlier than created {format_ts(si['created'])} (also what an ordinary copy looks like)")
    present = [v for v in (si["created"], si["modified"], si["accessed"]) if v is not None]
    if len(present) >= 2 and all(has_zero_subsecond(v) for v in present) and all(v > YEAR_1980_NS for v in present):
        fn_vals = [v for v in fn.values() if v is not None]
        if rec.source == "mft_export" and fn_vals and any(not has_zero_subsecond(v) for v in fn_vals):
            add("zero_subsecond", "all $SI times have a zero sub-second part while $FN times do not (typical of tools that write whole seconds)")
        else:
            add("zero_subsecond_no_fn", "all $SI times are whole seconds (weak: FAT volumes and unzip also do this)")
    bad = [(k, v) for k, v in {**{"si_" + k: v for k, v in si.items()}, **{"fn_" + k: v for k, v in fn.items()}}.items()
           if v is not None and v < YEAR_1980_NS]
    if bad:
        add("impossible_value", "timestamp before 1980 (zero/epoch value): " + ", ".join(f"{k}={format_ts(v, 0)}" for k, v in bad))
    if acquired_ns is not None:
        fut = [(k, v) for k, v in si.items() if v is not None and v > acquired_ns + future_slack_days * DAY_NS]
        if fut:
            add("future_timestamp", "timestamp after the evidence was acquired: " + ", ".join(f"{k}={format_ts(v, 0)}" for k, v in fut))
    if embedded and embedded.get("modified") is not None and si["modified"] is not None:
        if embedded["modified"] > si["modified"] + embedded_slack_days * DAY_NS:
            add("embedded_later_than_modified", f"document metadata says last saved {format_ts(embedded['modified'], 0)}, later than the file system modified time {format_ts(si['modified'], 0)}")
    return res
