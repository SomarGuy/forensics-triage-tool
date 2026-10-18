"""Windows Recycle Bin ``$I`` metadata files.

When a file is deleted to the Recycle Bin, Windows renames the content to ``$R<id><ext>`` and writes
``$I<id><ext>`` holding the original path, size and deletion time. Two layouts exist:

* version 1 (Vista to 8.1): fixed 544 bytes, 520-byte UTF-16LE path
* version 2 (Windows 10+): path length (in characters) followed by a variable-length UTF-16LE path

If the ``$I`` file survives but the ``$R`` file is gone (bin emptied selectively, secure-deleted), the
record proves a file existed and was deleted even though the content is no longer there.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from .timeutil import filetime_to_ns, ns_to_filetime


class RecycleParseError(ValueError):
    pass


@dataclass
class RecycleRecord:
    version: int
    original_size: int
    deleted_ns: int
    original_path: str


def parse_i_file(data: bytes) -> RecycleRecord:
    if len(data) < 24:
        raise RecycleParseError("too short for a $I file")
    version, size, ft = struct.unpack("<qqq", data[:24])
    if version == 1:
        raw = data[24:24 + 520]
        if len(raw) < 2:
            raise RecycleParseError("version 1 file has no path")
        path = raw.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
    elif version == 2:
        if len(data) < 28:
            raise RecycleParseError("version 2 file has no path length")
        nchars = struct.unpack("<I", data[24:28])[0]
        if nchars == 0 or nchars > 32768 or len(data) < 28 + nchars * 2:
            raise RecycleParseError("version 2 path length is inconsistent with file size")
        path = data[28:28 + nchars * 2].decode("utf-16-le", errors="replace").rstrip("\x00")
    else:
        raise RecycleParseError(f"unknown $I version {version}")
    if size < 0:
        raise RecycleParseError("negative size")
    return RecycleRecord(version, size, filetime_to_ns(ft), path)


def build_i_file(path: str, size: int, deleted_ns: int, version: int = 2) -> bytes:
    """Used by the synthetic generator and the tests to write a valid $I file."""
    head = struct.pack("<qqq", version, size, ns_to_filetime(deleted_ns))
    if version == 1:
        raw = (path.encode("utf-16-le") + b"\x00\x00")[:520]
        return head + raw.ljust(520, b"\x00")
    raw = path.encode("utf-16-le") + b"\x00\x00"
    return head + struct.pack("<I", len(path) + 1) + raw
