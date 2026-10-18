"""Data classes shared by the analysis modules and the report."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .fsmeta import FsRecord
from .timestomp import TimestompResult
from .timeutil import format_ts, to_ms


@dataclass
class FileRecord:
    path: str
    size: int
    md5: str
    sha1: str
    sha256: str
    ext: str
    detected_type: str
    detected_desc: str
    expected_types: List[str]
    mismatch: Optional[dict]
    hash_status: str                      # known_bad | known_good | ""
    hash_label: str
    fs: FsRecord
    timestomp: TimestompResult
    embedded: Dict[str, int] = field(default_factory=dict)
    flags: List[str] = field(default_factory=list)
    suppressed: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        fs = self.fs
        return {
            "path": self.path, "size": self.size, "md5": self.md5, "sha1": self.sha1, "sha256": self.sha256,
            "ext": self.ext, "detected_type": self.detected_type, "detected": self.detected_desc,
            "expected_types": self.expected_types, "mismatch": self.mismatch,
            "hash_status": self.hash_status, "hash_label": self.hash_label,
            "metadata_source": fs.source,
            "times": {
                "si": {k: format_ts(v) for k, v in fs.si.items()},
                "fn": {k: format_ts(v) for k, v in fs.fn.items()} if fs.has_fn else None,
            },
            "embedded": {k: format_ts(v, 0) for k, v in self.embedded.items()},
            "timestomp": {"score": self.timestomp.score, "verdict": self.timestomp.verdict, "indicators": self.timestomp.indicators},
            "flags": self.flags, "suppressed": self.suppressed,
        }


@dataclass
class Finding:
    rule: str
    title: str
    severity: str
    category: str
    summary: str
    first_seen: Optional[int] = None
    last_seen: Optional[int] = None
    files: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    mitre: List[dict] = field(default_factory=list)
    response: List[str] = field(default_factory=list)
    id: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id, "rule": self.rule, "title": self.title, "severity": self.severity, "category": self.category,
            "summary": self.summary, "first_seen": format_ts(self.first_seen, 0), "last_seen": format_ts(self.last_seen, 0),
            "first_seen_ms": to_ms(self.first_seen), "files": self.files, "evidence": self.evidence,
            "mitre": self.mitre, "response": self.response,
        }


@dataclass
class TimelineEvent:
    time_ns: int
    source: str          # FILESYSTEM | NTFS $FN | BROWSER | PREFETCH | REGISTRY | RECYCLE BIN | DOCUMENT | MFT
    category: str        # filesystem | browser | execution | usb | deletion | document
    description: str
    path: str = ""
    macb: str = ""
    anomalous: bool = False

    def to_dict(self) -> dict:
        return {"time": format_ts(self.time_ns), "ms": to_ms(self.time_ns), "source": self.source, "category": self.category,
                "macb": self.macb, "path": self.path, "description": self.description, "anomalous": self.anomalous}
