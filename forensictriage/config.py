"""Load and validate the triage configuration (thresholds, lists, finding rules)."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "triage_config.json"
SEVERITIES = ("critical", "high", "medium", "low")
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
REQUIRED_LISTS = [
    "file_sharing_domains", "webmail_domains", "job_search_domains", "archive_tools", "anti_forensic_tools",
    "staging_dir_patterns", "sensitive_name_patterns", "document_extensions", "noise_url_hosts",
    "internal_email_domains", "search_patterns",
]
REQUIRED_THRESHOLDS = ["min_string_length", "max_scan_bytes", "timestomp_likely_score", "fn_tolerance_seconds",
                       "embedded_slack_days", "future_slack_days", "staging_min_files", "correlation_window_hours", "usb_recent_days"]


class ConfigError(ValueError):
    pass


def validate(cfg: Dict[str, Any]) -> List[str]:
    problems: List[str] = []
    if not isinstance(cfg, dict):
        return ["configuration must be a JSON object"]
    for key in REQUIRED_THRESHOLDS:
        v = cfg.get("thresholds", {}).get(key)
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            problems.append(f"thresholds.{key} must be a non-negative integer")
    lists = cfg.get("lists", {})
    for key in REQUIRED_LISTS:
        if key not in lists:
            problems.append(f"lists.{key} is missing")
    for key in ("staging_dir_patterns", "sensitive_name_patterns"):
        for pat in lists.get(key, []):
            try:
                re.compile(pat)
            except re.error as exc:
                problems.append(f"lists.{key}: bad regex {pat!r}: {exc}")
    for cat, pats in lists.get("search_patterns", {}).items():
        for pat in pats:
            try:
                re.compile(pat)
            except re.error as exc:
                problems.append(f"lists.search_patterns.{cat}: bad regex {pat!r}: {exc}")
    mitre = cfg.get("mitre", {})
    seen = set()
    for r in cfg.get("rules", []):
        rid = r.get("id", "?")
        if rid in seen:
            problems.append(f"duplicate rule id {rid}")
        seen.add(rid)
        for k in ("id", "title", "severity", "category", "description", "response", "mitre"):
            if k not in r:
                problems.append(f"rule {rid}: missing '{k}'")
        if r.get("severity") not in SEVERITIES:
            problems.append(f"rule {rid}: severity must be one of {', '.join(SEVERITIES)}")
        if not r.get("response"):
            problems.append(f"rule {rid}: needs at least one response step")
        for t in r.get("mitre", []):
            if t not in mitre:
                problems.append(f"rule {rid}: technique {t} is not defined in 'mitre'")
    return problems


def load_config(path=None) -> Dict[str, Any]:
    p = Path(path) if path else DEFAULT_CONFIG_PATH
    try:
        cfg = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"configuration file not found: {p}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{p}: invalid JSON: {exc}") from exc
    problems = validate(cfg)
    if problems:
        raise ConfigError(f"{p}: " + "; ".join(problems))
    cfg["_rules_by_id"] = {r["id"]: r for r in cfg["rules"]}
    return cfg
