"""Multi-algorithm file hashing and known-bad / known-good hash lists."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

from .safeio import open_readonly

CHUNK = 1024 * 1024
_HEX = {32: "md5", 40: "sha1", 64: "sha256"}


@dataclass(frozen=True)
class Digests:
    md5: str
    sha1: str
    sha256: str
    size: int


def hash_bytes(data: bytes) -> Digests:
    return Digests(
        hashlib.md5(data, usedforsecurity=False).hexdigest(),
        hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        hashlib.sha256(data).hexdigest(),
        len(data),
    )


def hash_file(path) -> Digests:
    """Hash a file with MD5, SHA-1 and SHA-256 in a single read-only pass."""
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    size = 0
    with open_readonly(path) as fh:
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return Digests(md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest(), size)


@dataclass(frozen=True)
class HashMatch:
    category: str      # "known_bad" | "known_good"
    algorithm: str
    label: str


class HashList:
    """Hash sets, one hash per line: ``<hex>  <label>``. Lines starting with # are comments.

    Also accepts ``sha256sum`` style lines (``<hex> *<filename>``). The algorithm is inferred from the hex length.
    """

    def __init__(self) -> None:
        self._index: Dict[Tuple[str, str], HashMatch] = {}
        self.skipped = 0
        self.loaded = {"known_bad": 0, "known_good": 0}

    def add(self, category: str, digest: str, label: str = "") -> bool:
        digest = digest.strip().lower()
        algo = _HEX.get(len(digest))
        if not algo or not re.fullmatch(r"[0-9a-f]+", digest):
            self.skipped += 1
            return False
        key = (algo, digest)
        existing = self._index.get(key)
        if existing and existing.category == "known_bad" and category != "known_bad":
            return True  # known-bad always wins
        self._index[key] = HashMatch(category, algo, label.strip() or digest[:12])
        self.loaded[category] += 1
        return True

    def load_file(self, category: str, path) -> int:
        n = 0
        with open_readonly(path) as fh:
            text = fh.read().decode("utf-8", errors="replace")
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            label = parts[1].lstrip("*").strip() if len(parts) > 1 else ""
            if self.add(category, parts[0], label):
                n += 1
        return n

    def lookup(self, d: Digests) -> Optional[HashMatch]:
        found = None
        for algo, value in (("sha256", d.sha256), ("sha1", d.sha1), ("md5", d.md5)):
            m = self._index.get((algo, value))
            if m is not None:
                if m.category == "known_bad":
                    return m
                found = found or m
        return found

    def lookup_hex(self, value: str) -> Optional[HashMatch]:
        value = value.lower()
        algo = _HEX.get(len(value))
        return self._index.get((algo, value)) if algo else None

    def __len__(self) -> int:
        return len(self._index)
