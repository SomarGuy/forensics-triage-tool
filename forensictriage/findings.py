"""Turn the raw analysis results into findings (rule-driven; text, severity and MITRE mapping come from the config)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .config import SEVERITY_ORDER
from .models import FileRecord, Finding
from .signatures import extension
from .timeutil import NS, format_ts

HOUR_NS = 3600 * NS


@dataclass
class Analysis:
    cfg: Dict[str, Any]
    acquired_ns: Optional[int] = None
    files: List[FileRecord] = field(default_factory=list)
    recycle: List[dict] = field(default_factory=list)
    carved: List[dict] = field(default_factory=list)
    carve_stats: List[dict] = field(default_factory=list)
    browsers: List[Any] = field(default_factory=list)
    visit_hits: List[dict] = field(default_factory=list)
    search_hits: List[dict] = field(default_factory=list)
    prefetch: List[Any] = field(default_factory=list)
    registry: List[Any] = field(default_factory=list)
    usb: List[Any] = field(default_factory=list)
    recent_docs: List[Any] = field(default_factory=list)
    iocs: List[Any] = field(default_factory=list)
    mft_deleted: List[dict] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


def _make(cfg, rule_id: str, summary: str, *, severity: Optional[str] = None, title: Optional[str] = None, **kw) -> Finding:
    r = cfg["_rules_by_id"][rule_id]
    return Finding(
        rule=rule_id, title=title or r["title"], severity=severity or r["severity"], category=r["category"], summary=summary,
        mitre=[{"id": t, "name": cfg["mitre"][t]} for t in r["mitre"]], response=list(r["response"]), **kw,
    )


def _times(f: FileRecord) -> List[int]:
    return [v for v in list(f.fs.si.values()) + list(f.fs.fn.values()) if v is not None]


def _created(f: FileRecord) -> Optional[int]:
    return f.fs.fn.get("created") or f.fs.si.get("created") or f.fs.si.get("modified")


def _bounds(values: List[Optional[int]]):
    v = [x for x in values if x is not None]
    return (min(v), max(v)) if v else (None, None)


def _within(a: Optional[int], bs: List[int], window_ns: int) -> Optional[int]:
    if a is None:
        return None
    for b in bs:
        if abs(a - b) <= window_ns:
            return b
    return None


def build_findings(a: Analysis) -> List[Finding]:
    cfg, th, lists = a.cfg, a.cfg["thresholds"], a.cfg["lists"]
    out: List[Finding] = []
    window = th["correlation_window_hours"] * HOUR_NS

    # FT-001 known-bad hash
    for f in a.files:
        if f.hash_status == "known_bad":
            lo, hi = _bounds(_times(f))
            out.append(_make(cfg, "FT-001", f"{f.path} has a hash on the known-bad list ({f.hash_label}). SHA-256 {f.sha256}.",
                             title=f"File matches a known-bad hash: {f.path.rsplit('/', 1)[-1]}", files=[f.path],
                             evidence=[f"label: {f.hash_label}", f"md5 {f.md5}", f"sha1 {f.sha1}", f"sha256 {f.sha256}"],
                             first_seen=_created(f), last_seen=hi))

    # FT-002 signature mismatch (one per file)
    for f in a.files:
        if f.mismatch and "signature_mismatch" in f.flags:
            mm = f.mismatch
            out.append(_make(cfg, "FT-002", f"{f.path}: {mm['reason']}. Detected as {f.detected_desc}.", severity=mm["severity"],
                             title=f"Extension does not match content: {f.path.rsplit('/', 1)[-1]}", files=[f.path],
                             evidence=[f"extension .{f.ext} expects {', '.join(f.expected_types)}", f"content is {f.detected_type} ({f.detected_desc})", f"sha256 {f.sha256}"],
                             first_seen=_created(f), last_seen=_created(f)))

    # FT-003 / FT-004 timestomping
    weak: List[FileRecord] = []
    for f in a.files:
        if "timestomp_likely" in f.flags:
            out.append(_make(cfg, "FT-003", f"{f.path}: {len(f.timestomp.indicators)} timestamp indicators, score {f.timestomp.score}.",
                             title=f"Timestamps consistent with timestomping: {f.path.rsplit('/', 1)[-1]}", files=[f.path],
                             evidence=[f"{i['id']} (weight {i['weight']}): {i['detail']}" for i in f.timestomp.indicators],
                             first_seen=f.fs.fn.get("created") or _created(f), last_seen=f.fs.fn.get("created") or _created(f)))
        elif "timestamp_weak" in f.flags:
            weak.append(f)
    if weak:
        lo, hi = _bounds([_created(f) for f in weak])
        out.append(_make(cfg, "FT-004", f"{len(weak)} file(s) show a single weak timestamp anomaly (below the score of {th['timestomp_likely_score']}).",
                         files=[f.path for f in weak],
                         evidence=[f"{f.path}: " + "; ".join(i["id"] for i in f.timestomp.indicators) for f in weak], first_seen=lo, last_seen=hi))

    # FT-005 carved files
    complete = [c for c in a.carved if c["status"] == "complete"]
    partial = [c for c in a.carved if c["status"] == "partial"]
    notable = [c for c in complete if c.get("matches_file") or c.get("matches_recycle") or c.get("matches_mft")]
    for c in notable:
        bits = []
        if c.get("matches_recycle"):
            bits.append(f"size equals the Recycle Bin record for {c['matches_recycle']}")
        if c.get("matches_mft"):
            bits.append(f"size equals the deleted MFT entry {c['matches_mft']}")
        if c.get("matches_file"):
            bits.append(f"byte-identical (SHA-256) to existing file {c['matches_file']}")
        ev = [f"carved {c['name']} at offset {c['offset']} (0x{c['offset']:x}), {c['length']} bytes, {c['kind'].upper()}, validated={c['validated']}", f"sha256 {c['sha256']}"]
        ev += [b for b in bits]
        if c["kind"] == "zip" and c["details"].get("members"):
            ev.append("members: " + ", ".join(c["details"]["members"]))
        refs = [c["matches_file"]] if c.get("matches_file") else []
        out.append(_make(cfg, "FT-005", f"Recovered {c['kind'].upper()} {c['name']} from unallocated space: " + "; ".join(bits) + ".",
                         severity="high",
                         title=f"Deleted {c['kind'].upper()} recovered and matched to {(c.get('matches_recycle') or c.get('matches_mft') or c.get('matches_file')).replace(chr(92), '/').rsplit('/', 1)[-1]}",
                         files=refs, evidence=ev))
    rest = [c for c in complete if c not in notable]
    if rest or partial:
        ev = [f"{c['name']}: {c['kind'].upper()} {c['length']} bytes at 0x{c['offset']:x}, complete, sha256 {c['sha256'][:16]}…" for c in rest]
        ev += [f"{c['name']}: {c['kind'].upper()} {c['length']} bytes at 0x{c['offset']:x}, PARTIAL ({c['details'].get('reason', 'truncated')})" for c in partial]
        out.append(_make(cfg, "FT-005", f"{len(rest)} further complete file(s) and {len(partial)} partial file(s) were carved from unallocated space.",
                         title=f"{len(rest) + len(partial)} more deleted files recovered by carving", evidence=ev))

    # FT-006 recycle bin without content
    for r in a.recycle:
        if r.get("malformed") or r["content_present"]:
            continue
        ev = [f"original path {r['original_path']}", f"original size {r['original_size']} bytes", f"deleted {format_ts(r['deleted_ns'], 0)}", f"record {r['i_path']} (version {r['version']}); matching $R file is missing"]
        if r.get("matches_carved"):
            ev.append(f"content recovered by carving: {r['matches_carved']}")
        out.append(_make(cfg, "FT-006", f"{r['original_path']} was deleted at {format_ts(r['deleted_ns'], 0)} and its content is gone from the Recycle Bin.",
                         title=f"Recycle Bin record without content: {r['original_path'].rsplit(chr(92), 1)[-1]}", files=[r["i_path"]], evidence=ev,
                         first_seen=r["deleted_ns"], last_seen=r["deleted_ns"]))

    # execution times used for correlation
    exe_hits = {"archive": [], "antiforensic": []}
    for p in a.prefetch:
        name = p.executable.lower()
        if name in [t.lower() for t in lists["archive_tools"]]:
            exe_hits["archive"].append(p)
        if name in [t.lower() for t in lists["anti_forensic_tools"]]:
            exe_hits["antiforensic"].append(p)

    # FT-008 / FT-009
    for p in exe_hits["archive"]:
        out.append(_make(cfg, "FT-008", f"{p.executable} ran {p.run_count} time(s); last at {format_ts(p.last_runs_ns[-1], 0) if p.last_runs_ns else 'unknown'}.",
                         title=f"Archive utility executed: {p.executable}", evidence=[f"run {i + 1}: {format_ts(t, 0)}" for i, t in enumerate(p.last_runs_ns)] + ([f"path {p.path}"] if p.path else []),
                         first_seen=p.last_runs_ns[0] if p.last_runs_ns else None, last_seen=p.last_runs_ns[-1] if p.last_runs_ns else None))
    for p in exe_hits["antiforensic"]:
        out.append(_make(cfg, "FT-009", f"{p.executable} ran {p.run_count} time(s); last at {format_ts(p.last_runs_ns[-1], 0) if p.last_runs_ns else 'unknown'}.",
                         title=f"Anti-forensic / secure-deletion tool executed: {p.executable}", evidence=[f"run {i + 1}: {format_ts(t, 0)}" for i, t in enumerate(p.last_runs_ns)] + ([f"path {p.path}"] if p.path else []),
                         first_seen=p.last_runs_ns[0] if p.last_runs_ns else None, last_seen=p.last_runs_ns[-1] if p.last_runs_ns else None))

    # staging directory
    doc_ext = set(lists["document_extensions"])
    staging_re = [re.compile(p, re.I) for p in lists["staging_dir_patterns"]]
    sens_re = [re.compile(p, re.I) for p in lists["sensitive_name_patterns"]]
    by_dir: Dict[str, List[FileRecord]] = {}
    for f in a.files:
        d = f.path.rsplit("/", 1)[0] if "/" in f.path else ""
        if f.hash_status != "known_good" and any(rx.search(d + "/") for rx in staging_re) and f.ext in doc_ext:
            by_dir.setdefault(d, []).append(f)
    staging_times: List[int] = []
    for d, fs in sorted(by_dir.items()):
        if len(fs) < th["staging_min_files"]:
            continue
        for f in fs:
            f.flags.append("staging_dir")
        sens = [f for f in fs if any(rx.search(f.path) for rx in sens_re)]
        lo, hi = _bounds([_created(f) for f in fs])
        staging_times += [t for t in (lo, hi) if t is not None]
        out.append(_make(cfg, "FT-012", f"{len(fs)} document files ({len(sens)} with sensitive-looking names) sit in {d}.",
                         title=f"Staging directory: {d.rsplit('/', 1)[-1]}", files=[f.path for f in fs],
                         evidence=[f"{f.path} ({f.size} bytes, created {format_ts(_created(f), 0)})" for f in fs], first_seen=lo, last_seen=hi))

    # USB devices
    activity: List[int] = []
    for p in exe_hits["archive"] + exe_hits["antiforensic"]:
        activity += p.last_runs_ns
    activity += [r["deleted_ns"] for r in a.recycle if not r.get("malformed") and not r["content_present"]]
    activity += staging_times
    ref = a.acquired_ns
    for d in a.usb:
        seen = d.last_arrival_ns or d.first_install_ns
        if seen is None:
            continue
        if ref is not None and ref - seen > th["usb_recent_days"] * 24 * HOUR_NS:
            continue
        near = [t for t in activity if _within(seen, [t], window) is not None]
        sev = "high" if near else None
        recent = [v for v in a.recent_docs if d.drive_letter and v.value_data.lower().startswith(d.drive_letter.lower())]
        ev = [f"{d.vendor} {d.product} (serial {d.serial})"]
        if d.friendly_name:
            ev.append(f"friendly name: {d.friendly_name}")
        if d.drive_letter:
            ev.append(f"mounted as {d.drive_letter}")
        for label, t in (("first installed", d.first_install_ns), ("last arrival", d.last_arrival_ns), ("last removal", d.last_removal_ns)):
            if t is not None:
                ev.append(f"{label}: {format_ts(t, 0)}")
        ev += [f"recent document from the drive: {v.value_data}" for v in recent]
        if near:
            ev.append(f"coincides (within {th['correlation_window_hours']} h) with {len(near)} archiving / staging / deletion event(s)")
        out.append(_make(cfg, "FT-007", f"USB storage {d.vendor} {d.product} was connected{(' as ' + d.drive_letter) if d.drive_letter else ''} at {format_ts(seen, 0)}.",
                         severity=sev, title=f"USB storage connected: {d.vendor} {d.product} ({d.serial})", evidence=ev,
                         first_seen=d.first_install_ns or seen, last_seen=d.last_removal_ns or seen))

    # browser
    if a.visit_hits:
        by_cat: Dict[str, List[dict]] = {}
        for v in a.visit_hits:
            by_cat.setdefault(v["category"], []).append(v)
        ev = []
        for cat, vs in sorted(by_cat.items()):
            hosts = sorted({v["host"] for v in vs})
            ev.append(f"{cat}: {len(vs)} visit(s) to {', '.join(hosts)}")
        for v in a.visit_hits[:12]:
            ev.append(f"{format_ts(v['time_ns'], 0)}  {v['category']}  {v['url']}" + (f"  [{v['title']}]" if v["title"] else ""))
        ts = [v["time_ns"] for v in a.visit_hits if v["time_ns"]]
        if any(c in by_cat for c in ("file_sharing", "webmail")):
            out.append(_make(cfg, "FT-010", f"{len(a.visit_hits)} browser visit(s) to file-sharing / webmail / job-search domains.", evidence=ev,
                             first_seen=min(ts) if ts else None, last_seen=max(ts) if ts else None))
    if a.search_hits:
        sel = [s for s in a.search_hits if s["category"] in ("anti_forensics", "data_movement")]
        if sel:
            ts = [s["time_ns"] for s in sel if s["time_ns"]]
            out.append(_make(cfg, "FT-011", f"{len(sel)} search term(s) match anti-forensic or data-movement phrasing.",
                             evidence=[f"{format_ts(s['time_ns'], 0)}  [{s['category']}]  \"{s['term']}\"" for s in sel],
                             first_seen=min(ts) if ts else None, last_seen=max(ts) if ts else None))

    # IOCs
    ext = [i for i in a.iocs if i.type in ("url", "ipv4", "email") and i.scope == "external"]
    if ext:
        out.append(_make(cfg, "FT-013", f"{len(ext)} external indicator(s) (URLs, IPs, email addresses) were found in files.",
                         files=sorted({s.split("!")[0] for i in ext for s in i.sources if not s.startswith("carved:")}),
                         evidence=[f"{i.type} {i.value} (x{i.count}) in {', '.join(sorted(i.sources)[:3])}" for i in ext[:15]]))

    # MFT deleted
    if a.mft_deleted:
        lo, hi = _bounds([m.get("when_ns") for m in a.mft_deleted])
        out.append(_make(cfg, "FT-014", f"{len(a.mft_deleted)} file system entries are marked deleted and the files are not in the evidence tree.",
                         files=[m["path"] for m in a.mft_deleted],
                         evidence=[f"{m['path']} ({m.get('size')} bytes, record changed {format_ts(m.get('when_ns'), 0)})" for m in a.mft_deleted], first_seen=lo, last_seen=hi))

    # sort and number
    out.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.first_seen if f.first_seen is not None else 1 << 62, f.rule, f.title))
    for i, f in enumerate(out, 1):
        f.id = f"FND-{i:03d}"
    return out
