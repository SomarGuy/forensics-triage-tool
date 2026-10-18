"""The triage pipeline: open case, fingerprint evidence, analyse read-only, verify nothing changed, write outputs."""
from __future__ import annotations

import json
import mmap
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence

from . import __version__, TOOL_NAME
from .artifacts import ArtifactError, parse_prefetch_json, parse_registry_csv, recent_docs, usb_devices
from .browser import BrowserParseError, classify_visits, match_searches, parse_history
from .carve import CarveStats, carve_buffer
from .config import SEVERITY_ORDER, load_config
from .custody import CustodyLog
from .findings import Analysis, build_findings
from .fsmeta import FsMetaError, FsRecord, embedded_dates, norm_path, parse_mft_csv, stat_record
from .hashing import Digests, HashList, hash_bytes
from .integrity import Manifest, ManifestEntry, compare, snapshot, walk_files
from .iocs import IocCollector
from .models import FileRecord, Finding
from .recyclebin import RecycleParseError, parse_i_file
from .safeio import is_inside, open_readonly, read_capped
from .signatures import check_mismatch, detect_type, extension, EXPECTED
from .timeline import build_timeline
from .timestomp import assess
from .timeutil import format_ts, parse_ts


class TriageError(Exception):
    """Bad input or an unsafe configuration (for example output inside the evidence)."""


@dataclass
class CaseInputs:
    case_id: str
    root: Path
    title: str = ""
    examiner: str = ""
    description: str = ""
    synthetic: bool = False
    raw_images: List[Path] = field(default_factory=list)
    metadata: Optional[Path] = None
    prefetch: Optional[Path] = None
    registry: Optional[Path] = None
    known_bad: Optional[Path] = None
    known_good: Optional[Path] = None
    acquired_at: Optional[int] = None      # epoch ns, when the evidence was collected

    @classmethod
    def from_case_json(cls, path) -> "CaseInputs":
        path = Path(path)
        base = path.parent
        try:
            d = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise TriageError(f"cannot read case file {path}: {exc}") from exc
        for key in ("case_id", "evidence_root"):
            if key not in d:
                raise TriageError(f"{path}: missing '{key}'")

        def p(k):
            return (base / d[k]) if d.get(k) else None
        return cls(case_id=d["case_id"], root=base / d["evidence_root"], title=d.get("title", ""), examiner=d.get("examiner", ""),
                   description=d.get("description", ""), synthetic=bool(d.get("synthetic", False)),
                   raw_images=[base / x for x in d.get("raw_images", [])], metadata=p("metadata"), prefetch=p("prefetch"),
                   registry=p("registry"), known_bad=p("known_bad"), known_good=p("known_good"),
                   acquired_at=parse_ts(d.get("acquired_at")))


@dataclass
class CaseResult:
    inputs: CaseInputs
    analysis: Analysis
    findings: List[Finding]
    timeline: list
    before: Manifest
    after: Manifest
    differences: List[dict]
    custody: CustodyLog
    out_dir: Path
    files_written: List[str] = field(default_factory=list)
    started_ns: int = 0
    finished_ns: int = 0

    @property
    def integrity_ok(self) -> bool:
        return not self.differences


def _check_paths(inputs: CaseInputs, out_dir: Path) -> None:
    if not inputs.root.is_dir():
        raise TriageError(f"evidence root is not a directory: {inputs.root}")
    for label, p in (("raw image", inputs.raw_images), ("metadata export", [inputs.metadata]), ("prefetch export", [inputs.prefetch]),
                     ("registry export", [inputs.registry]), ("known-bad list", [inputs.known_bad]), ("known-good list", [inputs.known_good])):
        for x in p:
            if x is not None and not Path(x).is_file():
                raise TriageError(f"{label} not found: {x}")
    if is_inside(out_dir, inputs.root):
        raise TriageError(f"refusing to write output inside the evidence ({out_dir} is under {inputs.root}); choose another --out directory")
    guarded = [*inputs.raw_images, inputs.metadata, inputs.prefetch, inputs.registry, inputs.known_bad, inputs.known_good]
    for g in guarded:
        if g is not None and Path(g).resolve().parent == out_dir.resolve():
            raise TriageError(f"refusing to write output into the folder that holds an input file ({g}); choose another --out directory")


def _read_text(path) -> str:
    return read_capped(path, 64 << 20).decode("utf-8", errors="replace")


def _sid_of(rel: str) -> str:
    parts = rel.split("/")
    for i, part in enumerate(parts):
        if part.lower() == "$recycle.bin" and i + 1 < len(parts) - 1:
            return parts[i + 1]
    return ""


def run_triage(inputs: CaseInputs, out_dir, config_path=None, clock: Optional[Callable[[], int]] = None,
               write_outputs: bool = True) -> CaseResult:
    out_dir = Path(out_dir)
    cfg = load_config(config_path)
    th, lists = cfg["thresholds"], cfg["lists"]
    _check_paths(inputs, out_dir)
    clock = clock or time.time_ns
    started = clock()
    log = CustodyLog(inputs.case_id, clock)
    actor = f"{TOOL_NAME} {__version__}"
    log.record("CASE_OPENED", actor, "Case opened for read-only triage", examiner=inputs.examiner or "unspecified",
               synthetic=inputs.synthetic, evidence_root=inputs.root.name, python=sys.version.split()[0])

    # ---- 1. fingerprint everything before touching it
    def collect_items():
        """The evidence to fingerprint: every file under the root, plus raw images, exports and hash lists."""
        files, skips = walk_files(inputs.root)
        found = [(f"root/{p.relative_to(inputs.root).as_posix()}", "root", p) for p in files]
        found += [(f"raw/{p.name}", "raw", Path(p)) for p in inputs.raw_images]
        for p in (inputs.metadata, inputs.prefetch, inputs.registry):
            if p is not None:
                found.append((f"export/{Path(p).name}", "export", Path(p)))
        for p in (inputs.known_bad, inputs.known_good):
            if p is not None:
                found.append((f"reference/{Path(p).name}", "reference", Path(p)))
        return files, skips, found

    tree, skipped, items = collect_items()
    others = [Path(path).resolve().parent for label, kind, path in items if kind != "root"]
    base = Path(os.path.commonpath([str(inputs.root.resolve())] + [str(x) for x in others]))
    before = snapshot(items, base)
    before.skipped = skipped + before.skipped
    log.record("HASH_BEFORE", actor, f"Hashed {len(before.entries)} evidence and reference files before analysis (MD5, SHA-1, SHA-256)",
               files=len(before.entries), bytes=before.total_bytes, manifest_sha256=before.digest(), skipped=len(before.skipped))
    by_label = before.by_label()

    a = Analysis(cfg=cfg, acquired_ns=inputs.acquired_at)
    for s in skipped:
        a.notes.append(f"skipped {s['path']}: {s['reason']}")

    # ---- 2. reference data
    hashlist = HashList()
    for cat, p in (("known_bad", inputs.known_bad), ("known_good", inputs.known_good)):
        if p is not None:
            hashlist.load_file(cat, p)
    if hashlist.skipped:
        a.notes.append(f"{hashlist.skipped} line(s) in the hash lists were not valid hashes and were ignored")
    log.record("REFERENCE_LOADED", actor, f"Loaded hash lists: {hashlist.loaded['known_bad']} known-bad, {hashlist.loaded['known_good']} known-good", **hashlist.loaded)

    fs_by_path: Dict[str, FsRecord] = {}
    if inputs.metadata is not None:
        try:
            for r in parse_mft_csv(_read_text(inputs.metadata)):
                fs_by_path[r.path.lower()] = r
        except FsMetaError as exc:
            a.notes.append(f"metadata export could not be used ({exc}); falling back to os.stat timestamps")

    # ---- 3. per-file analysis
    cap = th["max_scan_bytes"]
    ioc = IocCollector(lists["noise_url_hosts"], lists["internal_email_domains"], hashlist, th["min_string_length"])
    tree_lower = {p.relative_to(inputs.root).as_posix().lower() for p in tree}
    for p in tree:
        rel = p.relative_to(inputs.root).as_posix()
        e = by_label.get(f"root/{rel}")
        if e is None:
            a.notes.append(f"{rel}: could not be read before analysis, so it was not analysed")
            continue
        try:
            dg = Digests(e.md5, e.sha1, e.sha256, e.size)
            parts = rel.split("/")
            is_recycle_i = any(x.lower() == "$recycle.bin" for x in parts) and parts[-1][:2].upper() == "$I"
            if is_recycle_i:      # metadata record that keeps the deleted file's extension; its content is not that format
                dtype, ddesc, mm = "recycle_i", "Recycle Bin $I metadata record", None
            else:
                dtype, ddesc = detect_type(p)
                mm = check_mismatch(rel, dtype)
            match = hashlist.lookup(dg)
            fs = fs_by_path.get(rel.lower()) or stat_record(p, rel)
            emb = embedded_dates(p, dtype) if dtype in ("docx", "xlsx", "pptx", "pdf") else {}
            ts = assess(fs, emb, inputs.acquired_at, cfg.get("timestomp_weights"), th["timestomp_likely_score"], th["fn_tolerance_seconds"],
                        th["embedded_slack_days"], th["future_slack_days"])
            rec = FileRecord(rel, e.size, e.md5, e.sha1, e.sha256, extension(rel), dtype, ddesc, list(EXPECTED.get(extension(rel), ())),
                             ({"severity": mm.severity, "reason": mm.reason} if mm else None),
                             match.category if match else "", match.label if match else "", fs, ts, emb)
            if rec.hash_status == "known_bad":
                rec.flags.append("known_bad")
            if rec.hash_status == "known_good":
                rec.flags.append("known_good")
                for what, present in (("signature_mismatch", mm), ("timestomp", ts.verdict != "none")):
                    if present:
                        rec.suppressed.append(what)
                mm = None
            else:
                if mm:
                    rec.flags.append("signature_mismatch")
                if ts.verdict == "likely":
                    rec.flags.append("timestomp_likely")
                elif ts.verdict == "weak":
                    rec.flags.append("timestamp_weak")
                if any(part.lower() == "$recycle.bin" for part in rel.split("/")):
                    rec.flags.append("recycle_bin")
                if dtype != "sqlite":
                    data = read_capped(p, cap)
                    ioc.scan_bytes(data, rel)
                    if dtype in ("zip", "docx", "xlsx", "pptx") and e.size <= cap:
                        ioc.scan_container(data, rel)
            a.files.append(rec)
        except OSError as exc:
            a.notes.append(f"{rel}: read error during analysis ({exc.strerror or exc}); file skipped")

    # ---- 4. recycle bin records
    for rec in a.files:
        parts = rec.path.split("/")
        if any(x.lower() == "$recycle.bin" for x in parts) and parts[-1][:2].upper() == "$I":
            r_name = "$R" + parts[-1][2:]
            r_path = "/".join(parts[:-1] + [r_name]).lower()
            item = {"i_path": rec.path, "sid": _sid_of(rec.path), "content_present": r_path in tree_lower}
            try:
                rr = parse_i_file(read_capped(inputs.root / rec.path, 8192))
                item.update(version=rr.version, original_path=rr.original_path, original_size=rr.original_size, deleted_ns=rr.deleted_ns)
            except (RecycleParseError, OSError) as exc:
                item.update(malformed=True, error=str(exc))
                a.notes.append(f"{rec.path}: malformed $I file ({exc})")
            a.recycle.append(item)

    # ---- 5. browser history, exports
    for rec in a.files:
        if rec.detected_type == "sqlite" and rec.hash_status != "known_good":
            try:
                b = parse_history(inputs.root / rec.path, rec.path)
            except BrowserParseError as exc:
                a.notes.append(f"{rec.path}: not parsed as browser history ({exc})")
                continue
            a.browsers.append(b)
            a.visit_hits += classify_visits(b, {"file_sharing": lists["file_sharing_domains"], "webmail": lists["webmail_domains"], "job_search": lists["job_search_domains"]})
            a.search_hits += match_searches(b, lists["search_patterns"])
            rec.flags.append("browser_history")
    a.visit_hits.sort(key=lambda v: v["time_ns"] or 0)
    a.search_hits.sort(key=lambda v: v["time_ns"] or 0)
    if inputs.prefetch is not None:
        try:
            a.prefetch = parse_prefetch_json(_read_text(inputs.prefetch))
        except ArtifactError as exc:
            a.notes.append(f"prefetch export could not be parsed: {exc}")
    if inputs.registry is not None:
        try:
            a.registry = parse_registry_csv(_read_text(inputs.registry))
            a.usb = usb_devices(a.registry)
            a.recent_docs = recent_docs(a.registry)
        except ArtifactError as exc:
            a.notes.append(f"registry export could not be parsed: {exc}")
    for fs in fs_by_path.values():
        if not fs.in_use and fs.path.lower() not in tree_lower:
            a.mft_deleted.append({"path": fs.path, "size": fs.size, "when_ns": fs.si.get("mft_changed") or fs.si.get("modified")})
    a.mft_deleted.sort(key=lambda m: (m["when_ns"] or 0, m["path"]))
    log.record("ANALYSIS_ARTEFACTS", actor,
               f"Analysed {len(a.files)} files; parsed {len(a.browsers)} browser DB(s), {len(a.prefetch)} prefetch entries, {len(a.registry)} registry values, {len(a.recycle)} Recycle Bin records",
               files=len(a.files), browsers=len(a.browsers), prefetch=len(a.prefetch), registry=len(a.registry), recycle=len(a.recycle))

    # ---- 6. carving (outputs go to out_dir/carved, never into the evidence)
    carved_dir = out_dir / "carved"
    for img in inputs.raw_images:
        img = Path(img)
        size = img.stat().st_size
        if size == 0:
            a.carve_stats.append({"image": img.name, **CarveStats().to_dict()})
            continue
        with open_readonly(img) as fh:
            mm_buf = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                results, stats = carve_buffer(mm_buf)
                a.carve_stats.append({"image": img.name, **stats.to_dict()})
                for n, c in enumerate(results, 1):
                    data = bytes(mm_buf[c.offset:c.end])
                    d = hash_bytes(data)
                    name = f"carved_{n:03d}_off{c.offset:08x}.{c.ext}"
                    m = hashlist.lookup(d)
                    entry = {"id": f"CF-{len(a.carved) + 1:03d}", "name": name, "image": img.name, "kind": c.kind, "offset": c.offset,
                             "length": c.length, "status": c.status, "validated": c.validated, "details": c.details,
                             "md5": d.md5, "sha1": d.sha1, "sha256": d.sha256, "hash_status": m.category if m else "", "hash_label": m.label if m else "",
                             "matches_file": "", "matches_recycle": "", "matches_mft": ""}
                    a.carved.append(entry)
                    if write_outputs:
                        carved_dir.mkdir(parents=True, exist_ok=True)
                        (carved_dir / name).write_bytes(data)
                    if c.status == "complete":
                        ioc.scan_bytes(data, f"carved:{name}")
                        if c.kind == "zip":
                            ioc.scan_container(data, f"carved:{name}")
            finally:
                mm_buf.close()
    sha_to_file = {}
    for rec in a.files:
        sha_to_file.setdefault(rec.sha256, rec.path)
    for c in a.carved:
        c["matches_file"] = sha_to_file.get(c["sha256"], "")
        for r in a.recycle:
            if not r.get("malformed") and not r["content_present"] and r["original_size"] == c["length"] and \
               extension(r["original_path"].replace("\\", "/")) == (c["kind"] if c["kind"] != "jpeg" else "jpg"):
                c["matches_recycle"] = r["original_path"]
                r["matches_carved"] = c["name"]
        for m in a.mft_deleted:
            if m.get("size") == c["length"] and extension(m["path"]) == (c["kind"] if c["kind"] != "jpeg" else "jpg") and not c["matches_recycle"]:
                c["matches_mft"] = m["path"]
    log.record("ANALYSIS_CARVING", actor, f"Carved {len(a.carved)} candidate file(s) from {len(inputs.raw_images)} raw image(s); written under the output folder only",
               carved=len(a.carved), complete=sum(1 for c in a.carved if c["status"] == "complete"), partial=sum(1 for c in a.carved if c["status"] == "partial"))

    a.iocs = ioc.results()
    log.record("ANALYSIS_IOCS", actor, f"Extracted {len(a.iocs)} distinct indicators ({ioc.noise_suppressed} noise URLs suppressed)", indicators=len(a.iocs))

    # ---- 7. findings + timeline
    findings = build_findings(a)
    timeline = build_timeline(a)

    # ---- 8. verify nothing changed
    _t2, _s2, items_after = collect_items()      # re-walk: files added during analysis must show up too
    after = snapshot(items_after, base)
    diffs = compare(before, after)
    log.record("HASH_AFTER", actor, f"Re-hashed {len(after.entries)} files after analysis", files=len(after.entries), manifest_sha256=after.digest())
    if diffs:
        log.record("VERIFY_FAILED", actor, f"{len(diffs)} difference(s) between the before and after hashes", differences=diffs[:20])
        cfg_rule = cfg["_rules_by_id"]["FT-900"]
        f = Finding("FT-900", cfg_rule["title"], "critical", cfg_rule["category"], f"{len(diffs)} evidence file(s) changed during analysis.",
                    files=[d["label"] for d in diffs], evidence=[f"{d['label']}: {d['change']} ({d['detail']})" for d in diffs],
                    response=list(cfg_rule["response"]))
        findings.insert(0, f)
        for i, x in enumerate(findings, 1):
            x.id = f"FND-{i:03d}"
    else:
        log.record("VERIFY_OK", actor, "Before and after manifests are identical (SHA-256, MD5, SHA-1, size, mtime, mode): evidence unchanged",
                   manifest_sha256=after.digest())
    res = CaseResult(inputs, a, findings, timeline, before, after, diffs, log, out_dir, started_ns=started, finished_ns=clock())
    if write_outputs:
        from .report import write_case_outputs
        write_case_outputs(res)
    return res
