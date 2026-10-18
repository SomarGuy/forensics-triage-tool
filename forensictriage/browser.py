"""Chrome-style browser history (SQLite) parser.

The database is opened with ``mode=ro&immutable=1`` so SQLite neither creates journal/WAL files next to
the evidence nor takes locks. Timestamps in Chrome are microseconds since 1601-01-01 (WebKit time).

Schema used (a subset of Chromium's ``History`` database):
``urls(id, url, title, visit_count, typed_count, last_visit_time, hidden)``,
``visits(id, url, visit_time, from_visit, transition, visit_duration)``,
``downloads(id, guid, current_path, target_path, start_time, end_time, received_bytes, total_bytes, state, danger_type, tab_url, referrer, mime_type)``,
``keyword_search_terms(keyword_id, url_id, term, normalized_term)``.
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence
from urllib.parse import urlsplit

from .timeutil import webkit_to_ns

TRANSITIONS = {0: "link", 1: "typed", 2: "auto_bookmark", 3: "auto_subframe", 4: "manual_subframe", 5: "generated",
               6: "start_page", 7: "form_submit", 8: "reload", 9: "keyword", 10: "keyword_generated"}
MAX_ROWS = 50_000


class BrowserParseError(Exception):
    pass


@dataclass
class BrowserData:
    path: str
    visits: List[dict] = field(default_factory=list)
    downloads: List[dict] = field(default_factory=list)
    searches: List[dict] = field(default_factory=list)
    urls: int = 0
    notes: List[str] = field(default_factory=list)


def _connect(path) -> sqlite3.Connection:
    uri = Path(path).resolve().as_uri() + "?mode=ro&immutable=1"
    return sqlite3.connect(uri, uri=True)


def _tables(con) -> set:
    return {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def parse_history(path, label: Optional[str] = None) -> BrowserData:
    label = label or str(path)
    try:
        con = _connect(path)
    except sqlite3.Error as exc:
        raise BrowserParseError(f"cannot open: {exc}") from exc
    data = BrowserData(label)
    try:
        tables = _tables(con)
        if not {"urls", "visits"} <= tables:
            raise BrowserParseError("no 'urls' and 'visits' tables: not a Chrome-style History database")
        data.urls = con.execute("SELECT COUNT(*) FROM urls").fetchone()[0]
        for vid, url, title, vt, trans, dur in con.execute(
            "SELECT v.id, u.url, u.title, v.visit_time, v.transition, v.visit_duration FROM visits v JOIN urls u ON u.id = v.url ORDER BY v.visit_time LIMIT ?",
            (MAX_ROWS,),
        ):
            data.visits.append({"id": vid, "url": url, "title": title or "", "host": host_of(url), "time_ns": webkit_to_ns(vt),
                                "transition": TRANSITIONS.get((trans or 0) & 0xFF, str((trans or 0) & 0xFF)),
                                "duration_s": round((dur or 0) / 1e6, 1)})
        if "downloads" in tables:
            for row in con.execute(
                "SELECT id, target_path, start_time, end_time, received_bytes, total_bytes, state, danger_type, tab_url, referrer, mime_type FROM downloads ORDER BY start_time LIMIT ?",
                (MAX_ROWS,),
            ):
                did, tp, st, et, rb, tb, state, danger, tab, ref, mime = row
                data.downloads.append({"id": did, "target_path": tp or "", "start_ns": webkit_to_ns(st), "end_ns": webkit_to_ns(et),
                                       "bytes": rb or 0, "total_bytes": tb or 0, "state": state, "danger_type": danger,
                                       "tab_url": tab or "", "referrer": ref or "", "mime_type": mime or "", "host": host_of(tab or "")})
        else:
            data.notes.append("no downloads table")
        if "keyword_search_terms" in tables:
            for term, url, vt in con.execute(
                "SELECT k.term, u.url, u.last_visit_time FROM keyword_search_terms k JOIN urls u ON u.id = k.url_id ORDER BY u.last_visit_time LIMIT ?",
                (MAX_ROWS,),
            ):
                data.searches.append({"term": term, "url": url, "time_ns": webkit_to_ns(vt), "host": host_of(url)})
        else:
            data.notes.append("no keyword_search_terms table")
    except sqlite3.Error as exc:
        raise BrowserParseError(f"database error: {exc}") from exc
    finally:
        con.close()
    return data


def classify_visits(data: BrowserData, domain_lists: Dict[str, Sequence[str]]) -> List[dict]:
    """Tag each visit/download with the first category whose domain list matches its host."""
    out = []
    for v in data.visits:
        for cat, domains in domain_lists.items():
            if any(v["host"] == d or v["host"].endswith("." + d) for d in domains):
                out.append(dict(v, category=cat))
                break
    return out


def match_searches(data: BrowserData, patterns: Dict[str, Sequence[str]]) -> List[dict]:
    out = []
    for s in data.searches:
        for cat, pats in patterns.items():
            if any(re.search(p, s["term"], re.I) for p in pats):
                out.append(dict(s, category=cat))
                break
    return out
