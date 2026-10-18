"""Chain-of-custody log: an append-only list of actions, each hash-linked to the one before it.

Every entry stores ``prev_hash`` and ``entry_hash = SHA-256(canonical JSON of the entry without its own hash)``.
Editing, deleting or re-ordering an entry breaks the chain, and ``verify_chain`` says where.
This detects accidental or casual tampering; it is not a signature, so someone who rewrites the whole
chain (and the report that quotes it) cannot be caught by this alone.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Callable, Dict, List, Optional, Tuple

from .timeutil import format_ts

GENESIS = "0" * 64


def _canonical(entry: dict) -> bytes:
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def compute_entry_hash(entry: dict) -> str:
    return hashlib.sha256(_canonical(entry)).hexdigest()


def verify_chain(entries: List[dict]) -> Tuple[bool, Optional[int], str]:
    """Return (ok, index_of_first_problem, reason)."""
    prev = GENESIS
    for i, e in enumerate(entries):
        if e.get("seq") != i + 1:
            return False, i, f"entry {i + 1}: sequence number is {e.get('seq')!r}, expected {i + 1}"
        if e.get("prev_hash") != prev:
            return False, i, f"entry {i + 1}: prev_hash does not match the previous entry"
        if compute_entry_hash(e) != e.get("entry_hash"):
            return False, i, f"entry {i + 1}: contents do not match entry_hash (entry was edited)"
        prev = e["entry_hash"]
    return True, None, "chain intact" if entries else "empty log"


class CustodyLog:
    def __init__(self, case_id: str, clock: Optional[Callable[[], int]] = None):
        self.case_id = case_id
        self._clock = clock or time.time_ns
        self.entries: List[dict] = []

    def record(self, action: str, actor: str, detail: str, **data) -> dict:
        entry = {
            "seq": len(self.entries) + 1,
            "time": format_ts(self._clock(), 3) + "Z",
            "case_id": self.case_id,
            "actor": actor,
            "action": action,
            "detail": detail,
            "data": data,
            "prev_hash": self.entries[-1]["entry_hash"] if self.entries else GENESIS,
        }
        entry["entry_hash"] = compute_entry_hash(entry)
        self.entries.append(entry)
        return entry

    def verify(self) -> Tuple[bool, Optional[int], str]:
        return verify_chain(self.entries)

    def to_list(self) -> List[dict]:
        return json.loads(json.dumps(self.entries))
