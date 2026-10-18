"""File signature (magic byte) analysis and extension / content mismatch checks."""
from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .safeio import open_readonly


@dataclass(frozen=True)
class Signature:
    type: str
    family: str          # image | document | archive | executable | database | media | text | unknown
    magic: bytes
    offset: int = 0
    description: str = ""


SIGNATURES: List[Signature] = [
    Signature("jpeg", "image", b"\xff\xd8\xff", 0, "JPEG image"),
    Signature("png", "image", b"\x89PNG\r\n\x1a\n", 0, "PNG image"),
    Signature("gif", "image", b"GIF87a", 0, "GIF image"),
    Signature("gif", "image", b"GIF89a", 0, "GIF image"),
    Signature("bmp", "image", b"BM", 0, "BMP image"),
    Signature("pdf", "document", b"%PDF-", 0, "PDF document"),
    Signature("rtf", "document", b"{\\rtf", 0, "Rich Text"),
    Signature("ole2", "document", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "OLE2 compound file (legacy Office)"),
    Signature("zip", "archive", b"PK\x03\x04", 0, "ZIP archive"),
    Signature("zip", "archive", b"PK\x05\x06", 0, "ZIP archive (empty)"),
    Signature("rar", "archive", b"Rar!\x1a\x07", 0, "RAR archive"),
    Signature("7z", "archive", b"7z\xbc\xaf\x27\x1c", 0, "7-Zip archive"),
    Signature("gzip", "archive", b"\x1f\x8b\x08", 0, "gzip"),
    Signature("pe", "executable", b"MZ", 0, "Windows PE executable / DLL"),
    Signature("elf", "executable", b"\x7fELF", 0, "ELF executable"),
    Signature("sqlite", "database", b"SQLite format 3\x00", 0, "SQLite database"),
    Signature("mp3", "media", b"ID3", 0, "MP3 audio"),
    Signature("mp4", "media", b"ftyp", 4, "MP4 / MOV container"),
]

# extension -> acceptable detected types
EXPECTED: Dict[str, Tuple[str, ...]] = {
    "jpg": ("jpeg",), "jpeg": ("jpeg",), "jpe": ("jpeg",),
    "png": ("png",), "gif": ("gif",), "bmp": ("bmp",),
    "pdf": ("pdf",), "rtf": ("rtf",),
    "doc": ("ole2",), "xls": ("ole2",), "ppt": ("ole2",),
    "docx": ("docx",), "xlsx": ("xlsx",), "pptx": ("pptx",),
    "zip": ("zip",), "rar": ("rar",), "7z": ("7z",), "gz": ("gzip",),
    "jar": ("zip",), "apk": ("zip",),
    "exe": ("pe", "mz"), "dll": ("pe", "mz"), "scr": ("pe", "mz"), "sys": ("pe", "mz"),
    "db": ("sqlite",), "sqlite": ("sqlite",), "mp3": ("mp3",), "mp4": ("mp4",), "mov": ("mp4",),
    "txt": ("text",), "csv": ("text",), "log": ("text",), "ini": ("text",), "json": ("text",), "xml": ("text",),
    "md": ("text",), "ps1": ("text",), "bat": ("text",), "cmd": ("text",), "py": ("text",), "js": ("text",),
    "html": ("text",), "htm": ("text",), "cfg": ("text",), "conf": ("text",), "reg": ("text",), "lnk": ("lnk",),
}
FAMILY_OF_TYPE = {
    "jpeg": "image", "png": "image", "gif": "image", "bmp": "image",
    "pdf": "document", "rtf": "document", "ole2": "document", "docx": "document", "xlsx": "document", "pptx": "document",
    "zip": "archive", "rar": "archive", "7z": "archive", "gzip": "archive",
    "pe": "executable", "mz": "executable", "elf": "executable", "sqlite": "database", "mp3": "media", "mp4": "media",
    "text": "text", "unknown": "unknown", "empty": "empty", "lnk": "document",
}
OOXML_PREFIX = {"word/": "docx", "xl/": "xlsx", "ppt/": "pptx"}


def extension(name: str) -> str:
    base = name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if "." not in base.strip("."):
        return ""
    return base.rsplit(".", 1)[-1].lower()


def _looks_like_text(head: bytes) -> bool:
    if not head:
        return False
    if head.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
        return True
    if b"\x00" in head:
        return False
    try:
        head.decode("utf-8")
        ok = True
    except UnicodeDecodeError:
        # a multi-byte character may be cut at the buffer edge; tolerate the last 3 bytes
        try:
            head[:-3].decode("utf-8")
            ok = True
        except UnicodeDecodeError:
            ok = False
    if not ok:
        return False
    printable = sum(1 for b in head if b in (9, 10, 13) or 32 <= b < 127 or b >= 128)
    return printable / len(head) > 0.95


def _refine_zip(path) -> str:
    """Tell OOXML (docx/xlsx/pptx) apart from a generic ZIP by looking at member names."""
    try:
        with open_readonly(path) as fh:
            with zipfile.ZipFile(fh) as zf:
                names = zf.namelist()
    except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError):
        return "zip"
    if "[Content_Types].xml" in names:
        for prefix, kind in OOXML_PREFIX.items():
            if any(n.startswith(prefix) for n in names):
                return kind
    return "zip"


def identify_bytes(head: bytes) -> Tuple[str, str]:
    """Return (type, description) from the first bytes alone."""
    if not head:
        return "empty", "empty file"
    for sig in SIGNATURES:
        end = sig.offset + len(sig.magic)
        if head[sig.offset:end] == sig.magic:
            if sig.type == "bmp" and not (len(head) >= 14 and head[6:10] == b"\x00\x00\x00\x00"):
                continue  # "BM" alone is just two letters; a real BMP has zeroed reserved fields
            if sig.type == "pe":
                lfanew = int.from_bytes(head[0x3C:0x40], "little") if len(head) >= 0x40 else 0
                if not (0x40 <= lfanew <= len(head) - 4 and head[lfanew:lfanew + 4] == b"PE\x00\x00"):
                    return "mz", "MZ header without a valid PE header (DOS stub or truncated file)"
            return sig.type, sig.description
    if _looks_like_text(head):
        return "text", "text"
    return "unknown", "no known signature"


def detect_type(path, head: Optional[bytes] = None) -> Tuple[str, str]:
    if head is None:
        with open_readonly(path) as fh:
            head = fh.read(4096)
    t, desc = identify_bytes(head)
    if t == "zip" and head.startswith(b"PK\x03\x04"):
        refined = _refine_zip(path)
        if refined != "zip":
            names = {"docx": "Word document (OOXML)", "xlsx": "Excel workbook (OOXML)", "pptx": "PowerPoint (OOXML)"}
            return refined, names[refined]
    return t, desc


@dataclass
class Mismatch:
    severity: str
    reason: str
    expected: List[str]
    detected: str


def check_mismatch(name: str, detected: str) -> Optional[Mismatch]:
    """Compare what the extension promises with what the bytes are. None means consistent or not assessable."""
    ext = extension(name)
    expected = EXPECTED.get(ext)
    if expected is None or detected == "empty":
        return None
    if detected in expected:
        return None
    exp_family = FAMILY_OF_TYPE.get(expected[0], "unknown")
    det_family = FAMILY_OF_TYPE.get(detected, "unknown")
    if detected == "zip" and expected[0] in ("docx", "xlsx", "pptx"):
        return Mismatch("medium", f".{ext} should be an OOXML package but the file is a plain ZIP", list(expected), detected)
    if detected == "text" and exp_family != "text" and ext not in ("lnk",):
        return Mismatch("medium", f".{ext} should be binary {expected[0]} but the content is plain text", list(expected), detected)
    if detected == "unknown":
        return Mismatch("medium", f".{ext} should be {expected[0]} but no known signature was found (corrupt, encrypted or wrong extension)", list(expected), detected)
    if det_family == "executable" and exp_family != "executable":
        return Mismatch("high", f"executable content disguised as .{ext}", list(expected), detected)
    if det_family == "archive" and exp_family in ("image", "document", "media", "text"):
        return Mismatch("high", f"{detected.upper()} archive disguised as .{ext}", list(expected), detected)
    if det_family == exp_family:
        return Mismatch("low", f"content is {detected} but the extension .{ext} suggests {expected[0]} (same kind of file)", list(expected), detected)
    return Mismatch("medium", f"content is {detected} but the extension .{ext} suggests {expected[0]}", list(expected), detected)
