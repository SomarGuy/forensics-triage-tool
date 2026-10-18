"""String extraction and indicator-of-compromise (IOC) extraction."""
from __future__ import annotations

import io
import ipaddress
import re
import zipfile
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

ASCII_RUN = re.compile(rb"[\x20-\x7e\t]{%d,}")
_REFANG = [(re.compile(r"hxxp", re.I), "http"), (re.compile(r"\[\.\]|\(\.\)|\[dot\]", re.I), "."), (re.compile(r"\[@\]|\[at\]", re.I), "@")]

URL_RE = re.compile(r"\bhttps?://[^\s\"'<>\)\]\}\\|^`]+", re.I)
EMAIL_RE = re.compile(r"(?<![\w.%+\-])[A-Za-z0-9][A-Za-z0-9._%+\-]*@[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w]|\.\d)")
HASH_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])")
_SEG = r"[\w .\-\$\(\)&@#%~+,;=!\[\]{}']"
_LAST = r"[\w.\-\$\(\)&@#%~+,;=!\[\]{}']"     # the final path element may not contain spaces, so prose after a path is not swallowed
WINPATH_RE = re.compile(r"(?<![A-Za-z])[A-Za-z]:\\(?:" + _SEG + r"+\\)*" + _LAST + r"*")

NOISE_IPS = {"0.0.0.0", "255.255.255.255"}


@dataclass
class IOC:
    type: str
    value: str
    scope: str = ""          # ipv4: internal | external ; url/email: external | internal
    count: int = 0
    sources: Set[str] = field(default_factory=set)
    known_bad: str = ""

    def to_dict(self, max_sources: int = 20) -> dict:
        src = sorted(self.sources)
        d = {"type": self.type, "value": self.value, "scope": self.scope, "count": self.count,
             "sources": src[:max_sources], "source_count": len(src)}
        if self.known_bad:
            d["known_bad"] = self.known_bad
        return d


def extract_strings(data: bytes, min_len: int = 6) -> List[Tuple[int, str, str]]:
    """ASCII and UTF-16LE printable strings as (offset, encoding, text)."""
    out: List[Tuple[int, str, str]] = []
    for m in re.finditer(ASCII_RUN.pattern % min_len, data):
        out.append((m.start(), "ascii", m.group().decode("ascii", "replace")))
    u16 = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    for m in u16.finditer(data):
        out.append((m.start(), "utf16le", m.group().decode("utf-16-le", "replace")))
    out.sort()
    return out


def refang(text: str) -> str:
    for rx, rep in _REFANG:
        text = rx.sub(rep, text)
    return text


def _host(url: str) -> str:
    m = re.match(r"https?://([^/:?#]+)", url, re.I)
    return m.group(1).lower() if m else ""


def _host_matches(host: str, domains: Iterable[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def classify_ip(ip: str) -> Optional[str]:
    """'internal', 'external', or None for noise such as 0.0.0.0 and loopback.

    Documentation ranges (RFC 5737) count as external: they stand in for public addresses in this project.
    """
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if ip in NOISE_IPS or a.is_loopback or a.is_unspecified or a.is_multicast:
        return None
    if a.is_private and not str(a).startswith(("192.0.2.", "198.51.100.", "203.0.113.")):
        return "internal"
    return "external"


class IocCollector:
    def __init__(self, noise_hosts: Sequence[str] = (), internal_domains: Sequence[str] = (), known_hashes=None,
                 min_string: int = 6):
        self.noise_hosts = [h.lower() for h in noise_hosts]
        self.internal_domains = [d.lower() for d in internal_domains]
        self.known_hashes = known_hashes
        self.min_string = min_string
        self.items: Dict[Tuple[str, str], IOC] = {}
        self.noise_suppressed = 0

    def _add(self, typ: str, value: str, scope: str, source: str, known_bad: str = "") -> None:
        key = (typ, value)
        ioc = self.items.get(key)
        if ioc is None:
            ioc = self.items[key] = IOC(typ, value, scope, known_bad=known_bad)
        ioc.count += 1
        ioc.sources.add(source)

    def scan_text(self, text: str, source: str) -> None:
        text = refang(text)
        url_spans: List[Tuple[int, int]] = []
        for m in URL_RE.finditer(text):
            url = m.group().rstrip(".,;:!?'\"")
            url_spans.append(m.span())
            host = _host(url)
            if not host or _host_matches(host, self.noise_hosts):
                self.noise_suppressed += 1
                continue
            scope = "internal" if _host_matches(host, self.internal_domains) else "external"
            self._add("url", url, scope, source)
        for m in EMAIL_RE.finditer(text):
            addr = m.group().lower()
            dom = addr.rsplit("@", 1)[1]
            scope = "internal" if _host_matches(dom, self.internal_domains) else "external"
            self._add("email", addr, scope, source)
        for m in IPV4_RE.finditer(text):
            scope = classify_ip(m.group())
            if scope is None:
                continue
            self._add("ipv4", m.group(), scope, source)
        for m in HASH_RE.finditer(text):
            h = m.group().lower()
            if h.isdigit() or h.isalpha():
                continue  # not plausible as a digest
            typ = {32: "md5", 40: "sha1", 64: "sha256"}[len(h)]
            bad = ""
            if self.known_hashes is not None:
                hit = self.known_hashes.lookup_hex(h)
                if hit and hit.category == "known_bad":
                    bad = hit.label
            self._add(typ, h, "", source, known_bad=bad)
        for m in WINPATH_RE.finditer(text):
            p = m.group().rstrip(" .")
            if len(p) > 3:
                self._add("windows_path", p, "", source)

    def scan_bytes(self, data: bytes, source: str) -> None:
        for _off, _enc, s in extract_strings(data, self.min_string):
            self.scan_text(s, source)

    def scan_container(self, data: bytes, source: str, max_members: int = 64, member_cap: int = 1 << 20) -> int:
        """Look inside ZIP-based containers (docx, xlsx, zip). Returns the number of members scanned."""
        scanned = 0
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for info in zf.infolist()[:max_members]:
                    if info.is_dir() or info.file_size > 64 * member_cap:
                        continue
                    try:
                        body = zf.read(info)[:member_cap]
                    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError, EOFError, ValueError):
                        continue
                    self.scan_bytes(body, f"{source}!{info.filename}")
                    scanned += 1
        except (zipfile.BadZipFile, ValueError, OSError, EOFError):
            pass
        return scanned

    def results(self) -> List[IOC]:
        order = {"url": 0, "ipv4": 1, "email": 2, "sha256": 3, "sha1": 4, "md5": 5, "windows_path": 6}
        return sorted(self.items.values(), key=lambda i: (order.get(i.type, 9), i.scope != "external", -i.count, i.value))
