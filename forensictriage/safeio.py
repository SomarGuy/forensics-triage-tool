"""Read-only file access. The tool never opens evidence for writing.

On Linux, ``O_NOATIME`` is used when permitted so that merely reading a file does not update its
access time. That flag only works for the file owner, so it silently falls back to a normal read-only
open. A real examiner would use a hardware or software write-blocker; this is a best-effort safeguard.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import BinaryIO

_NOATIME = getattr(os, "O_NOATIME", 0)
_BINARY = getattr(os, "O_BINARY", 0)


def open_readonly(path) -> BinaryIO:
    path = os.fspath(path)
    flags = os.O_RDONLY | _BINARY
    try:
        fd = os.open(path, flags | _NOATIME)
    except PermissionError:
        fd = os.open(path, flags)
    return os.fdopen(fd, "rb")


def read_head(path, n: int = 4096) -> bytes:
    with open_readonly(path) as fh:
        return fh.read(n)


def read_capped(path, limit: int) -> bytes:
    with open_readonly(path) as fh:
        return fh.read(limit)


def is_inside(child, parent) -> bool:
    """True when ``child`` is the same as, or inside, ``parent`` (after resolving symlinks)."""
    c, p = Path(child).resolve(), Path(parent).resolve()
    return c == p or p in c.parents
