import zipfile

import pytest

from forensictriage import synthetic as syn
from forensictriage.signatures import check_mismatch, detect_type, extension, identify_bytes


@pytest.mark.parametrize("data,expected", [
    (syn.jpeg_bytes("t"), "jpeg"), (syn.png_bytes("t"), "png"), (b"GIF89a\x01\x00\x01\x00", "gif"), (b"GIF87a....", "gif"),
    (syn.pdf_bytes("t", ["x"], "20260101000000", "20260101000000"), "pdf"), (b"{\\rtf1\\ansi hello}", "rtf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 20, "ole2"), (b"PK\x03\x04" + b"\x00" * 30, "zip"), (b"Rar!\x1a\x07\x00", "rar"),
    (b"7z\xbc\xaf\x27\x1c\x00\x04", "7z"), (b"\x1f\x8b\x08\x00", "gzip"), (b"\x7fELF\x02\x01", "elf"),
    (b"SQLite format 3\x00" + b"\x00" * 90, "sqlite"), (b"ID3\x03\x00", "mp3"), (b"\x00\x00\x00\x18ftypmp42", "mp4"),
])
def test_known_signatures(data, expected):
    assert identify_bytes(data)[0] == expected


def test_text_binary_empty_and_unknown():
    assert identify_bytes(b"")[0] == "empty"
    assert identify_bytes(b"hello world, this is plain text\n" * 5)[0] == "text"
    assert identify_bytes("caf\u00e9 cr\u00e8me br\u00fbl\u00e9e\n".encode() * 5)[0] == "text"
    assert identify_bytes(b"\xef\xbb\xbfBOM text")[0] == "text"
    assert identify_bytes(b"\xff\xfeh\x00i\x00")[0] == "text"
    assert identify_bytes(bytes(range(0, 256)) * 2)[0] == "unknown"
    assert identify_bytes(b"has\x00nul inside")[0] == "unknown"


def test_utf8_character_cut_at_buffer_edge_is_still_text():
    data = ("caf\u00e9 " * 100).encode()[:-1]            # last multi-byte char is cut in half
    assert identify_bytes(data)[0] == "text"


def test_invalid_utf8_is_not_text():
    assert identify_bytes(b"\xff\xfe\xfa" * 50 + b"abc")[0] == "text"      # starts with a UTF-16 BOM, so treated as text
    assert identify_bytes(b"abc" + b"\x80\x81\x82" * 80)[0] == "unknown"


def test_mz_needs_a_valid_pe_header_to_count_as_pe():
    dos = bytearray(b"MZ" + b"\x00" * 126)
    dos[0x3C:0x40] = (0x40).to_bytes(4, "little")
    dos[0x40:0x44] = b"PE\x00\x00"
    assert identify_bytes(bytes(dos))[0] == "pe"
    assert identify_bytes(b"MZ" + b"\x00" * 100)[0] == "mz"
    assert identify_bytes(b"MZ")[0] == "mz"
    assert identify_bytes(b"MZ is just two letters in a text file")[0] == "mz"      # honest: still an MZ header


def test_bmp_needs_zeroed_reserved_fields():
    bmp = b"BM" + b"\x36\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x36\x00\x00\x00" + b"\x28\x00\x00\x00"
    assert identify_bytes(bmp)[0] == "bmp"
    assert identify_bytes(b"BMW is a car maker, said the text file\n" * 3)[0] == "text"


def test_ooxml_is_told_apart_from_a_plain_zip(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(syn.docx_bytes("t", ["x"], "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"))
    assert detect_type(f)[0] == "docx"
    f.write_bytes(syn.xlsx_bytes("t", [["a"]], "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"))
    assert detect_type(f)[0] == "xlsx"
    f.write_bytes(syn.zip_bytes({"readme.txt": b"hi"}))
    assert detect_type(f)[0] == "zip"
    ppt = syn.zip_bytes({"[Content_Types].xml": b"<x/>", "ppt/presentation.xml": b"<x/>"})
    f.write_bytes(ppt)
    assert detect_type(f)[0] == "pptx"


def test_corrupt_zip_falls_back_to_zip(tmp_path):
    f = tmp_path / "bad.docx"
    f.write_bytes(b"PK\x03\x04" + b"garbage" * 20)
    assert detect_type(f)[0] == "zip"


@pytest.mark.parametrize("name,ext", [("a.JPG", "jpg"), ("dir.v2/file.tar.gz", "gz"), ("noext", ""), (".hidden", ""), ("C:\\x\\y.PDF", "pdf"), ("trailing.", "")])
def test_extension(name, ext):
    assert extension(name) == ext


def test_mismatch_matrix():
    assert check_mismatch("a.jpg", "jpeg") is None
    assert check_mismatch("a.jpeg", "jpeg") is None
    assert check_mismatch("a.docx", "docx") is None
    assert check_mismatch("a.unknownext", "zip") is None             # extension not assessable
    assert check_mismatch("a.jpg", "empty") is None
    m = check_mismatch("holiday.jpg", "zip")
    assert m.severity == "high" and "archive disguised" in m.reason
    m = check_mismatch("invoice.pdf", "pe")
    assert m.severity == "high" and "executable" in m.reason
    assert check_mismatch("invoice.pdf", "mz").severity == "high"
    assert check_mismatch("profile.png", "jpeg").severity == "low"
    assert check_mismatch("a.docx", "zip").severity == "medium"
    assert check_mismatch("a.pdf", "text").severity == "medium"
    assert check_mismatch("a.jpg", "unknown").severity == "medium"
    assert check_mismatch("a.mp3", "pdf").severity == "medium"
    assert check_mismatch("a.exe", "pe") is None and check_mismatch("a.exe", "mz") is None
    assert check_mismatch("notes.txt", "pe").severity == "high"
    assert check_mismatch("a.lnk", "text").severity == "medium"
