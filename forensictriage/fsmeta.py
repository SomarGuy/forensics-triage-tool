"""File system metadata: an NTFS-style ($MFT export) CSV, with a plain ``os.stat`` fallback.

A real MFT record carries two sets of timestamps: ``$STANDARD_INFORMATION`` (SI; what Explorer shows and
what user-mode tools can rewrite) and ``$FILE_NAME`` (FN; maintained by the kernel). Comparing them is
one of the standard ways to spot timestomping, so the CSV reader keeps both.

Accepted columns (case-insensitive): ``path`` or ``ParentPath`` + ``FileName``; ``in_use``/``InUse``;
``size``/``FileSize``; ``si_created``/``Created0x10``; ``si_modified``/``LastModified0x10``;
``si_accessed``/``LastAccess0x10``; ``si_mft_changed``/``LastRecordChange0x10``; and the same four with
``fn_`` or ``0x30``. The 0x10/0x30 names follow the MFTECmd CSV style but this reader has only been
tested against the synthetic export in this repository.
"""
from __future__ import annotations

import csv
import io
import os
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .safeio import open_readonly, read_capped
from .timeutil import parse_ts, strip_comments

FIELDS = ["created", "modified", "accessed", "mft_changed"]
_ALIASES = {
    "si_created": ("si_created", "created0x10"), "si_modified": ("si_modified", "lastmodified0x10"),
    "si_accessed": ("si_accessed", "lastaccess0x10"), "si_mft_changed": ("si_mft_changed", "lastrecordchange0x10"),
    "fn_created": ("fn_created", "created0x30"), "fn_modified": ("fn_modified", "lastmodified0x30"),
    "fn_accessed": ("fn_accessed", "lastaccess0x30"), "fn_mft_changed": ("fn_mft_changed", "lastrecordchange0x30"),
    "in_use": ("in_use", "inuse"), "size": ("size", "filesize"), "path": ("path",),
    "parent": ("parentpath",), "name": ("filename",),
}


class FsMetaError(ValueError):
    pass


@dataclass
class FsRecord:
    path: str
    in_use: bool = True
    size: Optional[int] = None
    si: Dict[str, Optional[int]] = field(default_factory=lambda: {k: None for k in FIELDS})
    fn: Dict[str, Optional[int]] = field(default_factory=lambda: {k: None for k in FIELDS})
    source: str = "mft_export"      # mft_export | stat

    @property
    def has_fn(self) -> bool:
        return any(v is not None for v in self.fn.values())


def norm_path(p: str) -> str:
    p = p.strip().replace("\\", "/")
    p = re.sub(r"^[A-Za-z]:", "", p)
    p = re.sub(r"^\.(?=/)", "", p)
    return p.strip("/")


def _truthy(v: str) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "y", "t")


def parse_mft_csv(text: str) -> List[FsRecord]:
    reader = csv.DictReader(io.StringIO(strip_comments(text)))
    if not reader.fieldnames:
        raise FsMetaError("metadata export has no header row")
    lower = {f.strip().lower(): f for f in reader.fieldnames}
    col = {canon: next((lower[a] for a in aliases if a in lower), None) for canon, aliases in _ALIASES.items()}
    if not col["path"] and not (col["parent"] and col["name"]):
        raise FsMetaError("metadata export needs a 'path' column (or ParentPath + FileName)")
    if not (col["si_modified"] or col["si_created"]):
        raise FsMetaError("metadata export needs SI timestamp columns (si_created / si_modified)")
    out: List[FsRecord] = []
    for row in reader:
        if col["path"]:
            path = norm_path(row.get(col["path"]) or "")
        else:
            path = norm_path((row.get(col["parent"]) or "") + "/" + (row.get(col["name"]) or ""))
        if not path:
            continue
        rec = FsRecord(path)
        if col["in_use"]:
            rec.in_use = _truthy(row.get(col["in_use"]) or "1")
        if col["size"]:
            try:
                rec.size = int(row.get(col["size"]) or "")
            except ValueError:
                rec.size = None
        for f in FIELDS:
            for prefix, target in (("si_", rec.si), ("fn_", rec.fn)):
                c = col[prefix + f]
                target[f] = parse_ts(row.get(c)) if c else None
        out.append(rec)
    return out


def stat_record(path, rel: str) -> FsRecord:
    """Fallback when no MFT export covers a file: whatever the host file system reports."""
    st = os.stat(path)
    rec = FsRecord(norm_path(rel), True, st.st_size, source="stat")
    rec.si["modified"] = st.st_mtime_ns
    rec.si["accessed"] = st.st_atime_ns
    birth = getattr(st, "st_birthtime", None)
    if birth is not None:
        rec.si["created"] = int(birth * 1_000_000_000)
    # on Windows st_ctime is creation time, on POSIX it is the inode change time
    if os.name == "nt":
        rec.si["created"] = rec.si["created"] or st.st_ctime_ns
    else:
        rec.si["mft_changed"] = st.st_ctime_ns
    return rec


_CORE = {
    "created": re.compile(r"<dcterms:created[^>]*>([^<]+)<"),
    "modified": re.compile(r"<dcterms:modified[^>]*>([^<]+)<"),
}
_PDF_DATE = re.compile(rb"/(CreationDate|ModDate)\s*\(D:(\d{4})(\d{2})(\d{2})(\d{2})?(\d{2})?(\d{2})?")


def embedded_dates(path, ftype: str) -> Dict[str, int]:
    """Dates the document itself records (OOXML core properties, PDF Info dictionary), independent of the file system."""
    out: Dict[str, int] = {}
    try:
        if ftype in ("docx", "xlsx", "pptx"):
            with open_readonly(path) as fh, zipfile.ZipFile(fh) as zf:
                if "docProps/core.xml" in zf.namelist():
                    xml = zf.read("docProps/core.xml")[:65536].decode("utf-8", "replace")
                    for k, rx in _CORE.items():
                        m = rx.search(xml)
                        if m and parse_ts(m.group(1)) is not None:
                            out[k] = parse_ts(m.group(1))
        elif ftype == "pdf":
            size = os.path.getsize(path)
            with open_readonly(path) as fh:
                head = fh.read(32768)
                if size > 65536:
                    fh.seek(size - 32768)
                    head += fh.read(32768)
            for m in _PDF_DATE.finditer(head):
                y, mo, d, hh, mm, ss = (int(x) if x else 0 for x in m.groups()[1:])
                ts = parse_ts(f"{y:04d}-{mo:02d}-{d:02d} {hh:02d}:{mm:02d}:{ss:02d}")
                if ts is not None:
                    out["created" if m.group(1) == b"CreationDate" else "modified"] = ts
    except (zipfile.BadZipFile, OSError, KeyError, ValueError, NotImplementedError):
        pass
    return out
