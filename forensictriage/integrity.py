"""Evidence manifests and before/after verification ("nothing was modified")."""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .hashing import hash_file


@dataclass
class ManifestEntry:
    label: str          # stable identifier, e.g. "root/Users/x/file.docx"
    rel: str            # path relative to the manifest base
    kind: str           # root | raw | export | reference
    size: int
    mtime_ns: int
    mode: int
    md5: str
    sha1: str
    sha256: str

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class Manifest:
    entries: List[ManifestEntry] = field(default_factory=list)
    skipped: List[dict] = field(default_factory=list)   # symlinks and unreadable files

    @property
    def total_bytes(self) -> int:
        return sum(e.size for e in self.entries)

    def digest(self) -> str:
        """One SHA-256 over every (label, sha256, size) so the whole evidence set has a single fingerprint."""
        h = hashlib.sha256()
        for e in sorted(self.entries, key=lambda x: x.label):
            h.update(f"{e.label}\0{e.sha256}\0{e.size}\n".encode())
        return h.hexdigest()

    def by_label(self) -> Dict[str, ManifestEntry]:
        return {e.label: e for e in self.entries}

    def to_dict(self) -> dict:
        return {
            "files": len(self.entries),
            "bytes": self.total_bytes,
            "digest_sha256": self.digest(),
            "entries": [e.to_dict() for e in self.entries],
            "skipped": self.skipped,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Manifest":
        return cls([ManifestEntry(**e) for e in d.get("entries", [])], list(d.get("skipped", [])))


def walk_files(root) -> Tuple[List[Path], List[dict]]:
    """All regular files below ``root`` in sorted order. Symlinks are listed as skipped, never followed."""
    root = Path(root)
    files: List[Path] = []
    skipped: List[dict] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for d in list(dirnames):
            if os.path.islink(os.path.join(dirpath, d)):
                skipped.append({"path": os.path.relpath(os.path.join(dirpath, d), root).replace(os.sep, "/"), "reason": "symlink to directory (not followed)"})
                dirnames.remove(d)
        for name in sorted(filenames):
            p = Path(dirpath) / name
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            if os.path.islink(p):
                skipped.append({"path": rel, "reason": "symlink (not followed)"})
            elif p.is_file():
                files.append(p)
    return files, skipped


def snapshot(items: Iterable[Tuple[str, str, Path]], base) -> Manifest:
    """Hash and stat each ``(label, kind, path)``. ``base`` only affects the stored relative path."""
    base = Path(base)
    m = Manifest()
    for label, kind, path in items:
        try:
            st = os.stat(path)
            d = hash_file(path)
        except OSError as exc:
            m.skipped.append({"path": label, "reason": f"unreadable: {exc.strerror or exc}"})
            continue
        try:
            rel = os.path.relpath(path, base).replace(os.sep, "/")
        except ValueError:
            rel = str(path)
        m.entries.append(ManifestEntry(label, rel, kind, d.size, st.st_mtime_ns, st.st_mode & 0o7777, d.md5, d.sha1, d.sha256))
    return m


def compare(before: Manifest, after: Manifest) -> List[dict]:
    """List every difference between two manifests. Empty list means the evidence is unchanged."""
    diffs: List[dict] = []
    b, a = before.by_label(), after.by_label()
    for label in sorted(b):
        if label not in a:
            diffs.append({"label": label, "change": "missing", "detail": "present before analysis, absent after"})
            continue
        x, y = b[label], a[label]
        if x.sha256 != y.sha256 or x.md5 != y.md5 or x.sha1 != y.sha1:
            diffs.append({"label": label, "change": "content", "detail": f"sha256 {x.sha256[:12]}… -> {y.sha256[:12]}…"})
        elif x.size != y.size:
            diffs.append({"label": label, "change": "size", "detail": f"{x.size} -> {y.size}"})
        else:
            extra = []
            if x.mtime_ns != y.mtime_ns:
                extra.append(f"mtime {x.mtime_ns} -> {y.mtime_ns}")
            if x.mode != y.mode:
                extra.append(f"mode {x.mode:o} -> {y.mode:o}")
            if extra:
                diffs.append({"label": label, "change": "metadata", "detail": "; ".join(extra)})
    for label in sorted(set(a) - set(b)):
        diffs.append({"label": label, "change": "added", "detail": "appeared during analysis"})
    return diffs
