"""Signature-based file carving from a raw buffer (an unallocated-space dump or a disk image).

Carving ignores the file system: it looks for known header bytes and then works out where the file
ends by following the format's own structure, not by guessing:

* JPEG: walks marker segments (so a thumbnail embedded in EXIF does not end the file early) and the
  entropy-coded scan data until the real EOI marker.
* PNG:  walks chunks and verifies each chunk's CRC-32 until IEND.
* PDF:  finds ``%%EOF`` and keeps going when it is followed by an incremental update.
* ZIP:  finds an End Of Central Directory record whose offsets agree with the header position, then
        checks the result with ``zipfile`` (CRC test of every member).

Results are ``complete`` (a valid end was found) or ``partial`` (valid structure up to a point, then it
breaks, which is what a file overwritten by something else looks like). Headers that lead nowhere are
counted as rejected false positives.
"""
from __future__ import annotations

import io
import re
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple, Union

Buffer = Union[bytes, bytearray, memoryview]

DEFAULT_MAX_SIZE = {"jpeg": 32 << 20, "png": 32 << 20, "pdf": 64 << 20, "zip": 256 << 20}
MIN_PARTIAL = 64
EXT = {"jpeg": "jpg", "png": "png", "pdf": "pdf", "zip": "zip"}

HEADERS = [
    ("jpeg", re.compile(rb"\xff\xd8\xff[\xc0-\xfe]")),
    ("png", re.compile(rb"\x89PNG\r\n\x1a\n")),
    ("pdf", re.compile(rb"%PDF-\d\.\d")),
    ("zip", re.compile(rb"PK\x03\x04")),
]


@dataclass
class Carved:
    kind: str
    offset: int
    length: int
    status: str                      # complete | partial
    validated: bool = False
    details: Dict[str, object] = field(default_factory=dict)

    @property
    def end(self) -> int:
        return self.offset + self.length

    @property
    def ext(self) -> str:
        return EXT[self.kind]


@dataclass
class CarveStats:
    bytes_scanned: int = 0
    headers_found: int = 0
    complete: int = 0
    partial: int = 0
    rejected: int = 0
    nested_skipped: int = 0

    def to_dict(self) -> dict:
        return dict(self.__dict__)


# --------------------------------------------------------------------------- JPEG
_SOF = set(range(0xC0, 0xD0)) - {0xC4, 0xC8, 0xCC}


def _jpeg_end(buf: Buffer, start: int, limit: int) -> Tuple[Optional[int], int, dict]:
    """Return (end_if_complete, last_good_offset, details)."""
    i = start + 2
    details: dict = {"segments": 0}
    last_good = start + 2
    n = limit
    while i + 1 < n:
        if buf[i] != 0xFF:
            return None, last_good, details
        while i + 1 < n and buf[i + 1] == 0xFF:  # fill bytes
            i += 1
        if i + 1 >= n:
            break
        m = buf[i + 1]
        if m == 0xD9:
            return i + 2, i + 2, details
        if m in (0x01, 0xD8) or 0xD0 <= m <= 0xD7:
            i += 2
            last_good = i
            continue
        if i + 4 > n:
            break
        seg_len = struct.unpack(">H", bytes(buf[i + 2:i + 4]))[0]
        if seg_len < 2 or i + 2 + seg_len > n:
            return None, last_good, details
        if m in _SOF and seg_len >= 8:
            h, w = struct.unpack(">HH", bytes(buf[i + 5:i + 9]))
            details.update(width=w, height=h)
        elif m == 0xE1 and bytes(buf[i + 4:i + 8]) == b"Exif":
            details["exif"] = True
        elif m == 0xFE:
            text = bytes(buf[i + 4:i + 2 + seg_len]).decode("latin-1", "replace").strip("\x00 ")
            details["comment"] = text[:80]
        details["segments"] += 1
        i += 2 + seg_len
        last_good = i
        if m == 0xDA:  # start of scan: skip entropy-coded data
            while True:
                j = _find(buf, b"\xff", i, n)
                if j < 0 or j + 1 >= n:
                    return None, last_good, details
                nxt = buf[j + 1]
                if nxt == 0x00 or 0xD0 <= nxt <= 0xD7:
                    i = j + 2
                elif nxt == 0xFF:
                    i = j + 1
                else:
                    i = j
                    break
            last_good = i
    return None, last_good, details


# --------------------------------------------------------------------------- PNG
def _png_end(buf: Buffer, start: int, limit: int) -> Tuple[Optional[int], int, dict]:
    pos = start + 8
    details: dict = {"chunks": 0}
    last_good = start + 8
    while pos + 12 <= limit:
        length = struct.unpack(">I", bytes(buf[pos:pos + 4]))[0]
        ctype = bytes(buf[pos + 4:pos + 8])
        if not re.fullmatch(rb"[A-Za-z]{4}", ctype) or length > 0x7FFFFFFF or pos + 12 + length > limit:
            return None, last_good, details
        data = bytes(buf[pos + 8:pos + 8 + length])
        crc = struct.unpack(">I", bytes(buf[pos + 8 + length:pos + 12 + length]))[0]
        if zlib.crc32(ctype + data) & 0xFFFFFFFF != crc:
            details["crc_error_in"] = ctype.decode()
            return None, last_good, details
        if ctype == b"IHDR" and length >= 8:
            details["width"], details["height"] = struct.unpack(">II", data[:8])
        details["chunks"] += 1
        pos += 12 + length
        last_good = pos
        if ctype == b"IEND":
            return pos, pos, details
    return None, last_good, details


# --------------------------------------------------------------------------- PDF
_OBJ_AFTER_EOF = re.compile(rb"\s*(?:\d+\s+\d+\s+obj\b|xref\b)")


def _pdf_end(buf: Buffer, start: int, limit: int) -> Tuple[Optional[int], int, dict]:
    details: dict = {}
    pos = start
    end = None
    updates = 0
    while True:
        j = _find(buf, b"%%EOF", pos, limit)
        if j < 0:
            break
        e = j + 5
        while e < limit and buf[e] in (0x0D, 0x0A) and e - (j + 5) < 2:
            e += 1
        end = e
        if _OBJ_AFTER_EOF.match(bytes(buf[e:e + 64])):
            updates += 1
            pos = e
            continue
        break
    if updates:
        details["incremental_updates"] = updates
    if end is not None:
        return end, end, details
    k = -1
    pos = start
    while True:
        j = _find(buf, b"endobj", pos, limit)
        if j < 0:
            break
        k, pos = j + 6, j + 6
    return None, (k if k > 0 else start + 8), details


# --------------------------------------------------------------------------- ZIP
def _zip_end(buf: Buffer, start: int, limit: int) -> Tuple[Optional[int], int, dict]:
    details: dict = {}
    pos = start
    while True:
        j = _find(buf, b"PK\x05\x06", pos, limit)
        if j < 0 or j + 22 > limit:
            break
        cd_size, cd_off, clen = struct.unpack("<IIH", bytes(buf[j + 12:j + 22]))
        ok_geometry = start + cd_off + cd_size == j and (cd_size == 0 or bytes(buf[start + cd_off:start + cd_off + 4]) == b"PK\x01\x02")
        if ok_geometry and j + 22 + clen <= limit:
            return j + 22 + clen, j + 22 + clen, details
        pos = j + 4
    # no valid end record: walk local file headers to see how far the structure holds
    p = start
    members = 0
    while p + 30 <= limit and bytes(buf[p:p + 4]) == b"PK\x03\x04":
        flags, = struct.unpack("<H", bytes(buf[p + 6:p + 8]))
        csize, = struct.unpack("<I", bytes(buf[p + 18:p + 22]))
        nlen, xlen = struct.unpack("<HH", bytes(buf[p + 26:p + 30]))
        if flags & 0x08:  # sizes live in a data descriptor; cannot walk further
            break
        nxt = p + 30 + nlen + xlen + csize
        if nxt > limit:
            break
        p, members = nxt, members + 1
    details["local_headers_walked"] = members
    return None, (p if members else start + 4), details


def _find(buf: Buffer, needle: bytes, start: int, end: int) -> int:
    f = getattr(buf, "find", None)
    if f is not None:
        return f(needle, start, end)
    return bytes(buf).find(needle, start, end)


FINDERS: Dict[str, Callable] = {"jpeg": _jpeg_end, "png": _png_end, "pdf": _pdf_end, "zip": _zip_end}


def validate(kind: str, data: bytes) -> Tuple[bool, dict]:
    """Independent check of a carved candidate."""
    if kind == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                bad = zf.testzip()
                names = zf.namelist()
        except (zipfile.BadZipFile, ValueError, NotImplementedError, OSError, EOFError) as exc:
            return False, {"zip_error": str(exc)[:80]}
        info = {"members": names[:50], "member_count": len(names)}
        if bad:
            info["bad_member"] = bad
        return bad is None, info
    if kind == "png":
        return data.endswith(b"IEND\xaeB`\x82"), {}
    if kind == "jpeg":
        return data.endswith(b"\xff\xd9"), {}
    if kind == "pdf":
        return b"%%EOF" in data[-16:], {}
    return False, {}


def carve_buffer(buf: Buffer, max_size: Optional[Dict[str, int]] = None) -> Tuple[List[Carved], CarveStats]:
    """Scan ``buf`` and return the carved files in offset order plus scan statistics."""
    sizes = dict(DEFAULT_MAX_SIZE)
    if max_size:
        sizes.update(max_size)
    stats = CarveStats(bytes_scanned=len(buf))
    hits: List[Tuple[int, str]] = []
    for kind, rx in HEADERS:
        for m in rx.finditer(buf):
            hits.append((m.start(), kind))
    hits.sort()
    stats.headers_found = len(hits)
    out: List[Carved] = []
    covered = 0
    for off, kind in hits:
        if off < covered:
            stats.nested_skipped += 1
            continue
        limit = min(len(buf), off + sizes[kind])
        end, last_good, details = FINDERS[kind](buf, off, limit)
        if end is not None:
            c = Carved(kind, off, end - off, "complete", details=details)
            stats.complete += 1
        elif last_good - off >= MIN_PARTIAL:
            c = Carved(kind, off, last_good - off, "partial", details=dict(details, reason="valid structure stops here; no valid end found"))
            stats.partial += 1
        else:
            stats.rejected += 1
            continue
        data = bytes(buf[c.offset:c.end])
        ok, extra = validate(kind, data)
        c.validated = ok and c.status == "complete"
        c.details.update(extra)
        if kind == "zip" and c.status == "complete" and not ok:
            c.status, c.validated = "partial", False
            c.details["reason"] = "end record found but archive failed its CRC / structure test"
            stats.complete -= 1
            stats.partial += 1
        out.append(c)
        covered = c.end
    return out, stats
