import io
import zipfile

import pytest

from forensictriage import synthetic as syn
from forensictriage.hashing import HashList, hash_bytes
from forensictriage.iocs import IocCollector, classify_ip, extract_strings, refang


def collect(text, **kw):
    c = IocCollector(kw.pop("noise", ["schemas.openxmlformats.org"]), kw.pop("internal", ["corp.example"]), kw.pop("hashes", None))
    c.scan_text(text, "src")
    return {(i.type, i.value): i for i in c.results()}


def test_strings_ascii_and_utf16():
    data = b"\x00\x01short\x00 a long ascii string here \x02" + "wide string value".encode("utf-16-le") + b"\xff"
    found = extract_strings(data, 6)
    kinds = {(enc, s) for _o, enc, s in found}
    assert ("ascii", " a long ascii string here ") in kinds
    assert ("utf16le", "wide string value") in kinds
    assert all(len(s) >= 6 for _o, _e, s in found)
    assert [o for o, _e, _s in found] == sorted(o for o, _e, _s in found)
    assert extract_strings(b"abc\x00def", 6) == []


def test_each_indicator_type():
    r = collect("see https://evil.example/a/b?x=1, mail bob@gmail.example ip 203.0.113.9 hash "
                + "d41d8cd98f00b204e9800998ecf8427e" + " " + "a" * 39 + "1" + " " + ("0123456789abcdef" * 4)
                + " path C:\\Windows\\System32\\cmd.exe done")
    assert ("url", "https://evil.example/a/b?x=1") in r
    assert r[("email", "bob@gmail.example")].scope == "external"
    assert r[("ipv4", "203.0.113.9")].scope == "external"
    assert ("md5", "d41d8cd98f00b204e9800998ecf8427e") in r
    assert ("sha1", "a" * 39 + "1") in r and ("sha256", "0123456789abcdef" * 4) in r
    assert ("windows_path", "C:\\Windows\\System32\\cmd.exe") in r


def test_scope_and_noise_rules():
    r = collect("http://schemas.openxmlformats.org/x user@corp.example http://intranet.corp.example/a 10.1.2.3 192.168.0.9 127.0.0.1 0.0.0.0 255.255.255.255 224.0.0.1")
    assert not any("schemas" in v for _t, v in r)
    assert r[("email", "user@corp.example")].scope == "internal" and r[("url", "http://intranet.corp.example/a")].scope == "internal"
    assert r[("ipv4", "10.1.2.3")].scope == "internal" and r[("ipv4", "192.168.0.9")].scope == "internal"
    assert not any(t == "ipv4" and v in ("127.0.0.1", "0.0.0.0", "255.255.255.255", "224.0.0.1") for t, v in r)


def test_documentation_ranges_count_as_external():
    assert classify_ip("203.0.113.5") == "external" and classify_ip("198.51.100.1") == "external" and classify_ip("192.0.2.1") == "external"
    assert classify_ip("8.8.8.8") == "external" and classify_ip("172.16.5.5") == "internal" and classify_ip("169.254.1.1") == "internal"
    assert classify_ip("not an ip") is None and classify_ip("127.0.0.2") is None


def test_version_numbers_and_bad_octets_are_not_ips():
    r = collect("version 1.2.3.4.5 and 999.1.1.1 and 1.2.3 and build 10.0.19045.1234x")
    assert not [k for k in r if k[0] == "ipv4"]


def test_digit_only_or_letter_only_hex_is_not_a_hash():
    r = collect("1" * 32 + " " + "a" * 40 + " " + "ab" * 32 + "0")
    assert not [k for k in r if k[0] in ("md5", "sha1", "sha256")]


def test_refang_and_trailing_punctuation():
    assert refang("hxxps://bad[.]example/x and a[@]b[.]com") == "https://bad.example/x and a@b.com"
    r = collect("(go to hxxp://bad[.]example/path). Then mail a[@]evil[.]example.")
    assert ("url", "http://bad.example/path") in r and ("email", "a@evil.example") in r


def test_urls_trailing_punctuation_and_case():
    r = collect('"http://Example.COM/a." and <https://x.example/b>; and https://y.example/c!')
    assert ("url", "http://Example.COM/a") in r and ("url", "https://x.example/b") in r and ("url", "https://y.example/c") in r


def test_windows_paths_with_spaces_and_unc_like_text():
    r = collect("opened C:\\Program Files\\7-Zip\\7zG.exe at 10:00 and D:\\ ok")
    assert ("windows_path", "C:\\Program Files\\7-Zip\\7zG.exe at 10") not in r
    assert any(k[0] == "windows_path" and k[1].startswith("C:\\Program Files\\7-Zip\\7zG.exe") for k in r)


def test_counts_and_sources_accumulate():
    c = IocCollector()
    c.scan_text("203.0.113.9 and 203.0.113.9", "a")
    c.scan_text("203.0.113.9", "b")
    i = c.results()[0]
    assert i.count == 3 and i.sources == {"a", "b"}
    d = i.to_dict(max_sources=1)
    assert d["sources"] == ["a"] and d["source_count"] == 2


def test_hash_ioc_known_bad_label():
    h = HashList()
    d = hash_bytes(b"bad-thing")
    h.add("known_bad", d.sha256, "BadThing")
    h.add("known_good", hash_bytes(b"fine").sha256, "Fine")
    r = collect(f"x {d.sha256} y {hash_bytes(b'fine').sha256}", hashes=h)
    assert r[("sha256", d.sha256)].known_bad == "BadThing" and r[("sha256", d.sha256)].to_dict()["known_bad"] == "BadThing"
    assert r[("sha256", hash_bytes(b"fine").sha256)].known_bad == ""


def test_container_scanning_looks_inside_zip_and_ooxml_but_filters_schema_noise():
    docx = syn.docx_bytes("t", ["upload to https://evil.example/drop and 203.0.113.77"], "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")
    c = IocCollector(["schemas.openxmlformats.org", "purl.org", "www.w3.org"])
    n = c.scan_container(docx, "doc.docx")
    assert n >= 3
    vals = {i.value for i in c.results()}
    assert {"https://evil.example/drop", "203.0.113.77"} <= vals
    assert not any("openxmlformats" in v or "purl.org" in v for v in vals)
    assert c.noise_suppressed > 0
    assert any(s.startswith("doc.docx!word/document.xml") for i in c.results() for s in i.sources)


def test_container_scanning_handles_deflated_bad_and_oversized_members():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", "http://deflated.example/x " * 5)
        zf.writestr("dir/", "")
        zf.writestr("big.txt", "x" * 5000)
    c = IocCollector()
    assert c.scan_container(buf.getvalue(), "z.zip", member_cap=100) == 2
    assert any(i.value == "http://deflated.example/x" for i in c.results())
    assert IocCollector().scan_container(b"PK\x03\x04junk", "bad.zip") == 0
    c2 = IocCollector()
    assert c2.scan_container(buf.getvalue(), "z.zip", max_members=1) == 1


def test_encrypted_member_is_skipped_without_crashing():
    import struct
    # a stored member flagged as encrypted (general purpose bit 0); zipfile raises RuntimeError on read
    data = bytearray(syn.zip_bytes({"s.txt": b"secret http://enc.example/x"}))
    data[6] |= 1
    cd = data.index(b"PK\x01\x02")
    data[cd + 8] |= 1
    assert IocCollector().scan_container(bytes(data), "enc.zip") == 0


def test_results_order_is_stable_and_groups_types():
    c = IocCollector()
    c.scan_text("C:\\a\\b.txt 203.0.113.9 a@b.example https://x.example/ 10.0.0.1", "s")
    assert [i.type for i in c.results()] == ["url", "ipv4", "ipv4", "email", "windows_path"]
    assert [i.scope for i in c.results() if i.type == "ipv4"] == ["external", "internal"]
