import io
import mmap
import struct
import zipfile
import zlib

import pytest

from forensictriage import synthetic as syn
from forensictriage.carve import Carved, carve_buffer, validate

PDF = syn.pdf_bytes("t", ["hello"], "20260101000000", "20260101000000")
PNG = syn.png_bytes("t")
JPG = syn.jpeg_bytes("t")
ZIP = syn.zip_bytes({"a.txt": b"hello" * 20, "b.bin": bytes(range(200))})
NOISE = bytes((i * 37 + 11) % 251 for i in range(3000))      # deterministic filler without signatures


def one(buf, **kw):
    res, stats = carve_buffer(buf, **kw)
    return res, stats


def test_each_type_is_carved_exactly_with_surrounding_noise():
    for kind, data in (("jpeg", JPG), ("png", PNG), ("pdf", PDF), ("zip", ZIP)):
        buf = NOISE[:700] + data + NOISE[:900]
        res, stats = one(buf)
        assert len(res) == 1, kind
        c = res[0]
        assert (c.kind, c.offset, c.length, c.status, c.validated) == (kind, 700, len(data), "complete", True)
        assert buf[c.offset:c.end] == data
        assert stats.complete == 1 and stats.partial == 0 and stats.rejected == 0


def test_all_four_in_one_image_in_offset_order():
    buf = NOISE + ZIP + NOISE + JPG + NOISE + PDF + NOISE + PNG + NOISE
    res, stats = one(buf)
    assert [c.kind for c in res] == ["zip", "jpeg", "pdf", "png"]
    assert [c.offset for c in res] == sorted(c.offset for c in res)
    assert stats.bytes_scanned == len(buf)


def test_jpeg_exif_thumbnail_does_not_end_the_file_early():
    data = syn.jpeg_bytes("with thumbnail", exif_thumbnail=True)
    assert data.count(b"\xff\xd9") >= 2                      # the embedded thumbnail has its own EOI
    res, stats = one(NOISE + data + NOISE)
    assert len(res) == 1 and res[0].length == len(data)
    assert res[0].details["exif"] is True and res[0].details["width"] == 16 and res[0].details["height"] == 16
    assert res[0].details["comment"].startswith("SYNTHETIC")
    assert stats.nested_skipped == 1                          # the thumbnail's own header is skipped, not carved separately


def test_truncated_jpeg_is_partial():
    res, _ = one(NOISE + JPG[:-40] + NOISE)
    assert len(res) == 1 and res[0].status == "partial" and res[0].validated is False


def test_png_with_bad_crc_is_partial_and_stops_at_the_last_good_chunk():
    bad = bytearray(PNG)
    idat = bytes(bad).index(b"IDAT")
    bad[idat + 6] ^= 0xFF
    res, _ = one(NOISE + bytes(bad) + NOISE)
    assert res[0].status == "partial"
    assert res[0].details["crc_error_in"] == "IDAT"
    assert res[0].length < len(PNG)


def test_png_trailing_bytes_are_not_included():
    res, _ = one(PNG + b"TRAILING JUNK" * 10)
    assert res[0].length == len(PNG)


def test_pdf_incremental_update_is_followed_to_the_last_eof():
    update = b"7 0 obj\n<< /Foo /Bar >>\nendobj\nxref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 8 >>\nstartxref\n999\n%%EOF\n"
    res, _ = one(NOISE + PDF + update + NOISE)
    assert res[0].length == len(PDF) + len(update)
    assert res[0].details["incremental_updates"] == 1


def test_pdf_without_eof_is_partial_up_to_last_endobj_or_rejected():
    cut = PDF[:PDF.index(b"xref")]
    res, stats = one(NOISE + cut + NOISE)
    assert res[0].status == "partial" and res[0].length == cut.rindex(b"endobj") + 6
    res, stats = one(NOISE + b"%PDF-1.4\n" + NOISE)
    assert res == [] and stats.rejected == 1


def test_pdf_with_embedded_jpeg_is_one_file_and_nested_header_skipped():
    pdf = syn.pdf_bytes("img", ["x"], "20260101000000", "20260101000000", jpeg=JPG)
    res, stats = one(NOISE + pdf + NOISE)
    assert [c.kind for c in res] == ["pdf"] and res[0].length == len(pdf)
    assert stats.nested_skipped == 1


def test_zip_with_comment_includes_the_comment():
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as zf:
        zf.writestr("x.txt", "data")
        zf.comment = b"a trailing archive comment"
    data = b.getvalue()
    res, _ = one(NOISE + data + NOISE)
    assert res[0].length == len(data) and res[0].validated


def test_zip_inside_zip_is_nested_not_carved_twice():
    inner = syn.zip_bytes({"i.txt": b"inner"})
    outer = syn.zip_bytes({"inner.zip": inner})
    res, stats = one(NOISE + outer + NOISE)
    assert len(res) == 1 and res[0].length == len(outer)
    assert stats.nested_skipped >= 1


def test_zip_with_corrupt_member_is_reported_partial_with_reason():
    data = bytearray(syn.zip_bytes({"a.txt": b"A" * 100}))
    data[data.index(b"A" * 100) + 5] = ord("B")             # stored data no longer matches its CRC
    res, stats = one(bytes(data))
    assert res[0].status == "partial" and res[0].validated is False
    assert "CRC" in res[0].details["reason"] or "bad_member" in res[0].details
    assert stats.complete == 0 and stats.partial == 1


def test_zip_without_end_record_walks_local_headers():
    data = syn.zip_bytes({"a.txt": b"A" * 300, "b.txt": b"B" * 300})
    cut = data[:data.index(b"PK\x01\x02")]                    # central directory and end record are gone
    res, _ = one(NOISE + cut + NOISE)
    assert res[0].status == "partial" and res[0].details["local_headers_walked"] == 2
    assert res[0].length == len(cut)


def test_zip_with_data_descriptor_stops_walking():
    hdr = bytearray(b"PK\x03\x04" + b"\x14\x00" + b"\x08\x00" + b"\x00" * 22 + b"\x01\x00\x00\x00" + b"a" + b"x" * 80)
    res, stats = one(NOISE + bytes(hdr) + NOISE)
    assert stats.rejected == 1


def test_decoys_are_rejected_not_carved():
    buf = NOISE + b"PK\x03\x04" + b"junk" * 10 + NOISE + b"\x89PNG\r\n\x1a\n" + b"junk" * 6 + NOISE + b"\xff\xd8\xff\xe1\x00\x01" + b"j" * 30 + NOISE
    res, stats = one(buf)
    assert res == [] and stats.rejected == 3 and stats.headers_found == 3


def test_empty_and_signature_free_buffers():
    res, stats = one(b"")
    assert res == [] and stats.bytes_scanned == 0 and stats.headers_found == 0
    res, stats = one(NOISE * 3)
    assert res == [] and stats.headers_found == 0


def test_size_cap_limits_how_far_the_scan_looks():
    res, _ = one(NOISE + PNG + NOISE, max_size={"png": 40})
    assert all(c.status != "complete" for c in res)


def test_works_on_an_mmap_like_the_real_pipeline(tmp_path):
    p = tmp_path / "img.dd"
    p.write_bytes(NOISE + JPG + NOISE + ZIP + NOISE)
    with open(p, "rb") as fh:
        mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        res, _ = carve_buffer(mm)
        mm.close()
    assert [c.kind for c in res] == ["jpeg", "zip"]


def test_validate_helper():
    assert validate("png", PNG)[0] and validate("jpeg", JPG)[0] and validate("pdf", PDF)[0]
    ok, info = validate("zip", ZIP)
    assert ok and info["member_count"] == 2 and info["members"] == ["a.txt", "b.bin"]
    assert not validate("zip", b"PK\x03\x04nonsense")[0]
    assert not validate("png", PNG[:-5])[0]
    assert validate("exe", b"")[0] is False


def test_carved_properties():
    c = Carved("jpeg", 10, 5, "complete")
    assert c.end == 15 and c.ext == "jpg"


def test_planted_files_in_the_synthetic_image_are_found_at_known_offsets(synth_dir, truth):
    data = (synth_dir / "unallocated" / "unallocated.dd").read_bytes()
    res, stats = carve_buffer(data)
    exp = truth["expected_carving"]
    assert (stats.complete, stats.partial, stats.rejected) == (exp["complete"], exp["partial"], exp["rejected"])
    assert stats.nested_skipped >= exp["nested_skipped_at_least"]
    assert {c.offset for c in res} == set(exp["offsets"].values())
    zipc = next(c for c in res if c.kind == "zip")
    assert zipc.validated and zipc.details["member_count"] == 3


def test_hand_built_jpeg_with_fill_bytes_restart_markers_and_stuffed_ff00():
    data = (b"\xff\xd8" + b"\xff\x01" + b"\xff\xff\xe0\x00\x04\xaa\xbb" + b"\xff\xda\x00\x04\xcc\xdd"
            + b"\x11\xff\x00\x22\xff\xd0\x33\xff\xff\xd9")
    res, stats = carve_buffer(b"\x00" * 100 + data + b"\x00" * 100)
    # header regex needs FFD8FF + marker byte: FFD8FF01 is below C0, so build with an APP0 first for the real test
    assert res == [] and stats.headers_found == 0
    data = (b"\xff\xd8" + b"\xff\xe0\x00\x04\xaa\xbb" + b"\xff\x01" + b"\xff\xff\xfe\x00\x04\xaa\xbb" + b"\xff\xda\x00\x04\xcc\xdd"
            + b"\x11\xff\x00\x22\xff\xd0\x33\xff\xff\xd9")
    pad = b"\x00" * 100
    res, stats = carve_buffer(pad + data + pad + pad)
    assert len(res) == 1 and res[0].offset == 100 and res[0].length == len(data) and res[0].status in ("complete", "partial")
    assert res[0].status == "complete"


def test_jpeg_with_impossible_segment_length_is_rejected():
    res, stats = carve_buffer(b"\x00" * 50 + b"\xff\xd8\xff\xe0\x00\x01" + b"\x00" * 50)
    assert res == [] and stats.rejected == 1
    res, stats = carve_buffer(b"\x00" * 50 + b"\xff\xd8\xff\xe0\xff\xf0" + b"\x00" * 10)
    assert res == [] and stats.rejected == 1


def test_png_chunk_with_garbage_type_is_rejected():
    res, stats = carve_buffer(b"\x00" * 20 + b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x05" + b"\x01\x02\x03\x04" + b"\x00" * 40)
    assert res == [] and stats.rejected == 1


def test_zip_end_record_with_wrong_geometry_is_not_trusted():
    data = bytearray(ZIP)
    eocd = bytes(data).rindex(b"PK\x05\x06")
    data[eocd + 16:eocd + 20] = (5).to_bytes(4, "little")        # central directory offset no longer matches
    res, _ = carve_buffer(NOISE + bytes(data) + NOISE)
    assert res and res[0].status == "partial"


def test_safeio_helpers(tmp_path):
    from forensictriage.safeio import is_inside, open_readonly, read_capped, read_head
    p = tmp_path / "a" / "f.bin"
    p.parent.mkdir()
    p.write_bytes(b"0123456789")
    assert read_head(p, 4) == b"0123" and read_capped(p, 100) == b"0123456789"
    assert is_inside(p, tmp_path) and is_inside(tmp_path, tmp_path) and not is_inside(tmp_path, p.parent)
    with open_readonly(p) as fh:
        with pytest.raises(Exception):
            fh.write(b"x")
