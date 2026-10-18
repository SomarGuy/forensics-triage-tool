"""Command-line interface: ``python -m forensictriage <command>``."""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__, synthetic
from .carve import carve_buffer
from .config import ConfigError, DEFAULT_CONFIG_PATH, SEVERITY_ORDER, SEVERITIES, load_config
from .custody import verify_chain
from .evaluate import evaluate, format_evaluation
from .hashing import hash_bytes
from .integrity import Manifest, compare, snapshot
from .report import build_report
from .timeutil import parse_ts
from .triage import CaseInputs, TriageError, run_triage

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE, EXIT_INTEGRITY = 0, 2, 3, 4
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEMO_CASE_DIR = PROJECT_ROOT / "data" / "synthetic" / f"case-{synthetic.CASE_ID}"
COLOUR = {"critical": "\033[1;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m"}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="forensictriage", description="Read-only digital forensics triage: hashing, file signatures, timestamps, carving, IOCs, artefacts, chain of custody.")
    p.add_argument("--version", action="version", version="forensictriage " + __version__)
    sub = p.add_subparsers(dest="command", required=True)

    t = sub.add_parser("triage", help="analyse evidence and write a case report")
    t.add_argument("--case", metavar="CASE_DIR_OR_JSON", help="a folder containing case.json (or the case.json itself); fills in all inputs")
    t.add_argument("--root", metavar="DIR", help="evidence folder (a mounted image or a directory tree)")
    t.add_argument("--raw", action="append", default=[], metavar="FILE", help="raw image or unallocated-space dump to carve (repeatable)")
    t.add_argument("--metadata", metavar="CSV", help="NTFS-style metadata export with $SI and $FN timestamps")
    t.add_argument("--prefetch", metavar="JSON", help="Prefetch-style export")
    t.add_argument("--registry", metavar="CSV", help="registry-style export")
    t.add_argument("--known-bad", metavar="FILE", help="hash list of known-bad files")
    t.add_argument("--known-good", metavar="FILE", help="hash list of known-good (baseline) files")
    t.add_argument("--case-id", default=None)
    t.add_argument("--examiner", default=None)
    t.add_argument("--acquired-at", metavar="'YYYY-MM-DD HH:MM:SS'", help="when the evidence was collected (UTC); used to spot future timestamps and recent USB use")
    t.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="detection configuration (default: config/triage_config.json)")
    t.add_argument("--out", required=True, metavar="DIR", help="output folder (must be outside the evidence)")
    t.add_argument("--dashboard-json", metavar="FILE", help="also copy case_report.json here (for the dashboard)")
    t.add_argument("--min-severity", choices=SEVERITIES, default="low", help="only print findings at or above this severity")
    t.add_argument("--fail-on", choices=SEVERITIES, default=None, help="exit with status 2 if any finding is at or above this severity")
    t.add_argument("--no-colour", action="store_true")

    c = sub.add_parser("carve", help="carve JPEG/PNG/PDF/ZIP files from a raw image")
    c.add_argument("image", metavar="IMAGE")
    c.add_argument("--out", required=True, metavar="DIR")
    c.add_argument("--dry-run", action="store_true", help="list what would be carved without writing files")

    v = sub.add_parser("verify", help="re-hash evidence against a saved evidence_manifest.json")
    v.add_argument("--manifest", required=True, metavar="FILE")
    v.add_argument("--base", required=True, metavar="DIR", help="folder the manifest's relative paths start from")
    v.add_argument("--content-only", action="store_true", help="ignore mtime/mode differences (for a copy or checkout); content, size, missing and added files still fail")

    vc = sub.add_parser("verify-custody", help="check that a custody_log.json hash chain is intact")
    vc.add_argument("log", metavar="FILE")

    r = sub.add_parser("list-rules", help="print the finding rules and the ATT&CK techniques they map to")
    r.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))

    vcf = sub.add_parser("validate-config", help="check a configuration file")
    vcf.add_argument("config", nargs="?", default=str(DEFAULT_CONFIG_PATH))

    g = sub.add_parser("generate", help="write the SYNTHETIC demonstration case")
    g.add_argument("--out", default=str(DEMO_CASE_DIR), metavar="DIR")
    g.add_argument("--seed", type=int, default=synthetic.SEED)

    d = sub.add_parser("demo", help="generate the synthetic case, triage it, evaluate against ground truth and refresh the dashboard data")
    d.add_argument("--case-dir", default=str(DEMO_CASE_DIR))
    d.add_argument("--reports-dir", default=str(PROJECT_ROOT / "reports"))
    d.add_argument("--dashboard-json", default=str(PROJECT_ROOT / "dashboard" / "data" / "case.json"))
    return p


def _colour(sev: str, text: str, on: bool) -> str:
    return f"{COLOUR[sev]}{text}\033[0m" if on and sev in COLOUR else text


def _print_summary(res, rep: dict, min_sev: str, colour: bool, out=None) -> None:
    out = out or sys.stdout
    s, m = rep["summary"], rep["meta"]
    print(f"Case {m['case_id']}" + ("  [SYNTHETIC DATA]" if m["synthetic"] else ""), file=out)
    print(f"  files {s['files']} | findings {s['findings']} (" + ", ".join(f"{s['by_severity'][k]} {k}" for k in SEVERITIES) + f") | carved {s['carved_complete']} complete + {s['carved_partial']} partial | indicators {s['iocs']}", file=out)
    ig = rep["integrity"]
    print(f"  evidence integrity: {'VERIFIED UNCHANGED' if ig['ok'] else 'CHANGED DURING ANALYSIS'}  (manifest sha256 {ig['after']['manifest_sha256'][:16]}…); custody chain: {ig['custody_chain_note']}", file=out)
    for f in rep["findings"]:
        if SEVERITY_ORDER[f["severity"]] <= SEVERITY_ORDER[min_sev]:
            print(f"  {f['id']} {_colour(f['severity'], '[' + f['severity'].upper() + ']', colour):<9} {f['rule']}  {f['title']}", file=out)
    print(f"  reports: {res.out_dir}", file=out)


def _cmd_triage(a, out=None) -> int:
    inputs: Optional[CaseInputs] = None
    if a.case:
        cp = Path(a.case)
        inputs = CaseInputs.from_case_json(cp / "case.json" if cp.is_dir() else cp)
    elif a.root:
        inputs = CaseInputs(case_id="ADHOC", root=Path(a.root))
    else:
        raise TriageError("give --case or --root")
    if a.root:
        inputs.root = Path(a.root)
    if a.raw:
        inputs.raw_images = [Path(x) for x in a.raw]
    for attr in ("metadata", "prefetch", "registry", "known_bad", "known_good"):
        v = getattr(a, attr)
        if v:
            setattr(inputs, attr, Path(v))
    if a.case_id:
        inputs.case_id = a.case_id
    if a.examiner:
        inputs.examiner = a.examiner
    if a.acquired_at:
        ts = parse_ts(a.acquired_at)
        if ts is None:
            raise TriageError(f"--acquired-at is not a valid timestamp: {a.acquired_at!r}")
        inputs.acquired_at = ts
    res = run_triage(inputs, a.out, a.config)
    rep = build_report(res)
    _print_summary(res, rep, a.min_severity, sys.stdout.isatty() and not a.no_colour, out)
    if a.dashboard_json:
        Path(a.dashboard_json).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(Path(a.out) / "case_report.json", a.dashboard_json)
    if not res.integrity_ok:
        return EXIT_INTEGRITY
    if a.fail_on and any(SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER[a.fail_on] for f in res.findings):
        return EXIT_FINDINGS
    return EXIT_OK


def _cmd_carve(a) -> int:
    from .safeio import open_readonly
    img = Path(a.image)
    if not img.is_file():
        raise TriageError(f"image not found: {img}")
    data = open_readonly(img).read()
    results, stats = carve_buffer(data)
    out = Path(a.out)
    if not a.dry_run:
        out.mkdir(parents=True, exist_ok=True)
    for n, c in enumerate(results, 1):
        blob = data[c.offset:c.end]
        d = hash_bytes(blob)
        name = f"carved_{n:03d}_off{c.offset:08x}.{c.ext}"
        if not a.dry_run:
            (out / name).write_bytes(blob)
        print(f"{name}  {c.kind:<4} {c.status:<8} offset {c.offset:#x}  {c.length} bytes  sha256 {d.sha256[:16]}…")
    print(f"{stats.complete} complete, {stats.partial} partial, {stats.rejected} rejected false positives, {stats.nested_skipped} nested headers skipped, {stats.bytes_scanned:,} bytes scanned")
    return EXIT_OK


def _cmd_verify(a) -> int:
    try:
        saved = Manifest.from_dict(json.loads(Path(a.manifest).read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        raise TriageError(f"cannot read manifest: {exc}") from exc
    base = Path(a.base)
    now = snapshot([(e.label, e.kind, base / e.rel) for e in saved.entries], base)
    diffs = compare(saved, now)
    if a.content_only:                      # a copy, checkout or unzip legitimately changes mtime and mode
        diffs = [d for d in diffs if d["change"] != "metadata"]
    if diffs:
        print(f"EVIDENCE CHANGED: {len(diffs)} difference(s)")
        for d in diffs:
            print(f"  {d['label']}: {d['change']} ({d['detail']})")
        return EXIT_INTEGRITY
    print(f"OK: {len(saved.entries)} files match the manifest" + (" by content and size" if a.content_only else "") + f" (manifest sha256 {saved.digest()[:16]}…)")
    return EXIT_OK


def _cmd_verify_custody(a) -> int:
    try:
        doc = json.loads(Path(a.log).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TriageError(f"cannot read custody log: {exc}") from exc
    entries = doc["entries"] if isinstance(doc, dict) else doc
    ok, idx, reason = verify_chain(entries)
    print(("OK: " if ok else "BROKEN: ") + reason + f" ({len(entries)} entries)")
    return EXIT_OK if ok else EXIT_INTEGRITY


def _cmd_list_rules(a) -> int:
    cfg = load_config(a.config)
    for r in cfg["rules"]:
        tech = ", ".join(r["mitre"]) or "-"
        print(f"{r['id']}  {r['severity']:<8} {r['title']}  [ATT&CK: {tech}]")
    return EXIT_OK


def _cmd_demo(a) -> int:
    case_dir = Path(a.case_dir)
    info = synthetic.generate(case_dir)
    print(f"Generated SYNTHETIC case in {case_dir} ({info['files']} files, {info['raw_bytes']:,}-byte raw image)")
    reports = Path(a.reports_dir)
    shutil.rmtree(reports / "carved", ignore_errors=True)
    inputs = CaseInputs.from_case_json(case_dir / "case.json")
    res = run_triage(inputs, reports)
    rep = build_report(res)
    _print_summary(res, rep, "low", False)
    truth = json.loads((case_dir / "ground_truth.json").read_text(encoding="utf-8"))
    ev = evaluate(rep, truth)
    (reports / "evaluation.json").write_text(json.dumps(ev, indent=2) + "\n", encoding="utf-8")
    print(format_evaluation(ev))
    Path(a.dashboard_json).parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(reports / "case_report.json", a.dashboard_json)
    print(f"Dashboard data written to {a.dashboard_json}")
    return EXIT_OK if (ev["passed"] and res.integrity_ok) else EXIT_FINDINGS


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "triage":
            return _cmd_triage(args)
        if args.command == "carve":
            return _cmd_carve(args)
        if args.command == "verify":
            return _cmd_verify(args)
        if args.command == "verify-custody":
            return _cmd_verify_custody(args)
        if args.command == "list-rules":
            return _cmd_list_rules(args)
        if args.command == "validate-config":
            cfg = load_config(args.config)
            print(f"OK: {len(cfg['rules'])} rules, {sum(len(v) if isinstance(v, list) else 0 for v in cfg['lists'].values())} list entries")
            return EXIT_OK
        if args.command == "generate":
            info = synthetic.generate(args.out, args.seed)
            print(f"Generated SYNTHETIC case in {args.out} ({info['files']} files)")
            return EXIT_OK
        if args.command == "demo":
            return _cmd_demo(args)
    except (TriageError, ConfigError, FileExistsError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    return EXIT_USAGE
