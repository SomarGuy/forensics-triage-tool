"""Build the combined timeline: file system MACB events plus browser, execution, USB, deletion and document events."""
from __future__ import annotations

from typing import Dict, List

from .findings import Analysis
from .models import TimelineEvent
from .timeutil import NS, format_ts
from .timestomp import YEAR_1980_NS

TOL = 2 * NS


def _macb(times: Dict[str, int]) -> Dict[int, str]:
    letters = {"modified": "M", "accessed": "A", "mft_changed": "C", "created": "B"}
    grouped: Dict[int, set] = {}
    for k, t in times.items():
        if t is not None:
            grouped.setdefault(t, set()).add(letters[k])
    return {t: "".join(l if l in s else "." for l in "MACB") for t, s in grouped.items()}


def build_timeline(a: Analysis) -> List[TimelineEvent]:
    ev: List[TimelineEvent] = []
    for f in a.files:
        base = f"{f.path} ({f.size} bytes)"
        for t, m in _macb(f.fs.si).items():
            ev.append(TimelineEvent(t, "FILESYSTEM", "filesystem", base, f.path, m, t < YEAR_1980_NS))
        if "timestomp_likely" in f.flags and f.fs.has_fn:
            for t, m in _macb(f.fs.fn).items():
                if all(abs(t - s) > TOL for s in f.fs.si.values() if s is not None):
                    ev.append(TimelineEvent(t, "NTFS $FN", "filesystem", f"{f.path}: $FILE_NAME time (not changed by user-mode tools), differs from $SI", f.path, m))
        if "timestomp_likely" in f.flags:
            for k, t in f.embedded.items():
                ev.append(TimelineEvent(t, "DOCUMENT", "document", f"{f.path}: document metadata says {k}", f.path))
    for b in a.browsers:
        search_urls = {s["url"] for s in b.searches}
        for v in b.visits:
            if v["time_ns"] is None or v["url"] in search_urls:
                continue
            ev.append(TimelineEvent(v["time_ns"], "BROWSER", "browser", f"Visited {v['url']}" + (f" ({v['title']})" if v["title"] else ""), b.path))
        for s in b.searches:
            if s["time_ns"]:
                ev.append(TimelineEvent(s["time_ns"], "BROWSER", "browser", f"Searched for \"{s['term']}\" on {s['host']}", b.path))
        for d in b.downloads:
            if d["start_ns"]:
                ev.append(TimelineEvent(d["start_ns"], "BROWSER", "browser", f"Downloaded to {d['target_path']} from {d['tab_url'] or 'unknown page'}", b.path))
    for p in a.prefetch:
        for i, t in enumerate(p.last_runs_ns):
            ev.append(TimelineEvent(t, "PREFETCH", "execution", f"Executed {p.executable} (run {i + 1} of {len(p.last_runs_ns)} recorded; {p.run_count} total)", p.path))
    for d in a.usb:
        for label, t in (("first installed", d.first_install_ns), ("connected", d.last_arrival_ns), ("removed", d.last_removal_ns)):
            if t:
                ev.append(TimelineEvent(t, "REGISTRY", "usb", f"USB storage {d.vendor} {d.product} ({d.serial}) {label}" + (f", drive {d.drive_letter}" if d.drive_letter else "")))
    for v in a.recent_docs:
        if v.last_write_ns:
            ev.append(TimelineEvent(v.last_write_ns, "REGISTRY", "usb", f"Recent document entry: {v.value_name} -> {v.value_data}"))
    for r in a.recycle:
        if not r.get("malformed"):
            state = "content still in bin" if r["content_present"] else "content missing"
            ev.append(TimelineEvent(r["deleted_ns"], "RECYCLE BIN", "deletion", f"Deleted: {r['original_path']} ({r['original_size']} bytes; {state})", r["i_path"]))
    for m in a.mft_deleted:
        if m.get("when_ns"):
            ev.append(TimelineEvent(m["when_ns"], "MFT", "deletion", f"MFT entry no longer in use (file deleted): {m['path']} ({m.get('size')} bytes)", m["path"]))
    ev.sort(key=lambda e: (e.time_ns, e.source, e.path, e.description))
    return ev
