"""Windows artefact exports: Prefetch-style JSON and registry-style CSV.

These are parsers for *exports* (as produced by common parsing tools), not for the binary Prefetch or
hive formats. Column names are matched case-insensitively with a few aliases.
"""
from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .timeutil import parse_ts, strip_comments


class ArtifactError(ValueError):
    pass


@dataclass
class PrefetchEntry:
    executable: str
    run_count: int
    last_runs_ns: List[int]
    path: str = ""
    files_loaded: List[str] = field(default_factory=list)


def parse_prefetch_json(text: str) -> List[PrefetchEntry]:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ArtifactError(f"prefetch export is not valid JSON: {exc}") from exc
    rows = doc.get("entries") if isinstance(doc, dict) else doc
    if not isinstance(rows, list):
        raise ArtifactError("prefetch export must be a list or an object with an 'entries' list")
    out: List[PrefetchEntry] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        low = {k.lower(): v for k, v in r.items()}
        exe = low.get("executable") or low.get("executablename") or low.get("name")
        if not exe:
            continue
        runs = low.get("last_run_times") or low.get("lastrun") or low.get("last_runs") or []
        if isinstance(runs, str):
            runs = [runs]
        times = sorted(t for t in (parse_ts(x) for x in runs) if t is not None)
        try:
            count = int(low.get("run_count", low.get("runcount", len(times))))
        except (TypeError, ValueError):
            count = len(times)
        out.append(PrefetchEntry(str(exe).upper(), count, times, str(low.get("path", "")), list(low.get("files_loaded", []) or [])))
    return out


_REG_ALIASES = {
    "key_path": ("key_path", "keypath", "key", "hive path"),
    "value_name": ("value_name", "valuename", "name"),
    "value_type": ("value_type", "valuetype", "type"),
    "value_data": ("value_data", "valuedata", "data"),
    "last_write_time": ("last_write_time", "lastwritetime", "lastwrite", "last_write"),
}


@dataclass
class RegistryValue:
    key_path: str
    value_name: str
    value_type: str
    value_data: str
    last_write_ns: Optional[int]


def parse_registry_csv(text: str) -> List[RegistryValue]:
    reader = csv.DictReader(io.StringIO(strip_comments(text)))
    if not reader.fieldnames:
        raise ArtifactError("registry export has no header row")
    cols: Dict[str, str] = {}
    for canon, aliases in _REG_ALIASES.items():
        for f in reader.fieldnames:
            if f.strip().lower() in aliases:
                cols[canon] = f
                break
    if "key_path" not in cols or "value_name" not in cols:
        raise ArtifactError("registry export needs at least key_path and value_name columns")
    out = []
    for row in reader:
        out.append(RegistryValue(
            (row.get(cols["key_path"]) or "").strip(),
            (row.get(cols["value_name"]) or "").strip(),
            (row.get(cols.get("value_type", ""), "") or "").strip(),
            (row.get(cols.get("value_data", ""), "") or "").strip(),
            parse_ts(row.get(cols.get("last_write_time", ""), "")),
        ))
    return out


_USB_KEY = re.compile(r"USBSTOR\\Disk&Ven_(?P<vendor>[^&\\]+)&Prod_(?P<product>[^&\\]+)(?:&Rev_(?P<rev>[^\\]+))?\\(?P<serial>[^\\]+)", re.I)


@dataclass
class UsbDevice:
    vendor: str
    product: str
    serial: str
    friendly_name: str = ""
    first_install_ns: Optional[int] = None
    last_arrival_ns: Optional[int] = None
    last_removal_ns: Optional[int] = None
    drive_letter: str = ""


def usb_devices(values: List[RegistryValue]) -> List[UsbDevice]:
    """Build USB storage device records from USBSTOR keys, MountedDevices and the like."""
    devices: Dict[str, UsbDevice] = {}
    for v in values:
        m = _USB_KEY.search(v.key_path)
        if not m:
            continue
        d = devices.setdefault(m["serial"], UsbDevice(m["vendor"].replace("_", " "), m["product"].replace("_", " "), m["serial"]))
        name = v.value_name.lower()
        if name == "friendlyname":
            d.friendly_name = v.value_data
        elif name == "firstinstalldate":
            d.first_install_ns = parse_ts(v.value_data)
        elif name == "lastarrivaldate":
            d.last_arrival_ns = parse_ts(v.value_data)
        elif name == "lastremovaldate":
            d.last_removal_ns = parse_ts(v.value_data)
    for v in values:
        m = re.search(r"\\DosDevices\\([A-Z]):", v.value_name, re.I)
        if m:
            for serial, d in devices.items():
                if serial.split("&")[0].lower() in v.value_data.lower():
                    d.drive_letter = m.group(1).upper() + ":"
    return sorted(devices.values(), key=lambda d: d.serial)


def recent_docs(values: List[RegistryValue]) -> List[RegistryValue]:
    return [v for v in values if "recentdocs" in v.key_path.lower() or "recent" in v.key_path.lower().split("\\")[-1]]
