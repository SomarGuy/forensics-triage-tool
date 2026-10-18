import copy
import json
import os
import stat

import pytest

from forensictriage.custody import GENESIS, CustodyLog, compute_entry_hash, verify_chain
from forensictriage.integrity import Manifest, compare, snapshot, walk_files


def make_log(n=4):
    ticks = iter(range(1_700_000_000_000_000_000, 1_700_000_000_000_000_000 + 10**9 * 100, 10**9))
    log = CustodyLog("C-1", clock=lambda: next(ticks))
    for i in range(n):
        log.record(f"ACTION_{i}", "tester", f"step {i}", n=i)
    return log


def test_chain_is_valid_and_deterministic_for_a_fixed_clock():
    a, b = make_log(), make_log()
    assert a.verify() == (True, None, "chain intact")
    assert [e["entry_hash"] for e in a.entries] == [e["entry_hash"] for e in b.entries]
    assert a.entries[0]["prev_hash"] == GENESIS
    assert a.entries[1]["prev_hash"] == a.entries[0]["entry_hash"]
    assert a.entries[0]["time"].endswith("Z")


def test_empty_log_is_valid():
    assert verify_chain([]) == (True, None, "empty log")


def test_editing_an_entry_is_detected_and_located():
    e = make_log().to_list()
    e[2]["detail"] = "step 2 (edited)"
    ok, idx, why = verify_chain(e)
    assert not ok and idx == 2 and "edited" in why


def test_editing_and_re_hashing_one_entry_breaks_the_next_link():
    e = make_log().to_list()
    e[1]["detail"] = "rewritten"
    e[1]["entry_hash"] = compute_entry_hash(e[1])
    ok, idx, why = verify_chain(e)
    assert not ok and idx == 2 and "prev_hash" in why


def test_deleting_or_reordering_entries_is_detected():
    e = make_log().to_list()
    del e[1]
    assert verify_chain(e)[0] is False
    e = make_log().to_list()
    e[1], e[2] = e[2], e[1]
    assert verify_chain(e)[0] is False


def test_truncating_the_tail_is_not_detectable_by_the_chain_alone():
    """Documented limit: a prefix of a valid chain is itself valid."""
    e = make_log().to_list()
    assert verify_chain(e[:2])[0] is True


def test_log_copy_is_independent():
    log = make_log()
    snap = log.to_list()
    snap[0]["detail"] = "changed"
    assert log.verify()[0]


# --------------------------------------------------------------------------- integrity
def tree(tmp_path):
    root = tmp_path / "ev"
    (root / "d").mkdir(parents=True)
    (root / "a.txt").write_bytes(b"alpha")
    (root / "d" / "b.bin").write_bytes(b"\x00\x01\x02" * 100)
    return root


def snap(root):
    files, skipped = walk_files(root)
    return snapshot([(f"root/{p.relative_to(root).as_posix()}", "root", p) for p in files], root), skipped


def test_walk_is_sorted_and_skips_symlinks(tmp_path):
    root = tree(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    try:
        os.symlink(outside, root / "link.txt")
        os.symlink(tmp_path, root / "dirlink")
    except OSError:
        pytest.skip("symlinks not available")
    files, skipped = walk_files(root)
    assert [p.relative_to(root).as_posix() for p in files] == ["a.txt", "d/b.bin"]
    assert {s["path"] for s in skipped} == {"link.txt", "dirlink"}
    assert all("not followed" in s["reason"] for s in skipped)


def test_unchanged_evidence_compares_equal_and_digest_is_stable(tmp_path):
    root = tree(tmp_path)
    a, _ = snap(root)
    b, _ = snap(root)
    assert compare(a, b) == [] and a.digest() == b.digest() and len(a.digest()) == 64
    assert a.total_bytes == 5 + 300


def test_content_change_with_same_size_and_restored_mtime_is_still_caught(tmp_path):
    root = tree(tmp_path)
    a, _ = snap(root)
    st = os.stat(root / "a.txt")
    (root / "a.txt").write_bytes(b"ALPHA")
    os.utime(root / "a.txt", ns=(st.st_atime_ns, st.st_mtime_ns))
    b, _ = snap(root)
    d = compare(a, b)
    assert [(x["label"], x["change"]) for x in d] == [("root/a.txt", "content")]
    assert a.digest() != b.digest()


def test_size_mtime_mode_missing_and_added_are_reported(tmp_path):
    root = tree(tmp_path)
    a, _ = snap(root)
    os.utime(root / "a.txt", ns=(1, 2))
    os.chmod(root / "d" / "b.bin", 0o600 if os.stat(root / "d" / "b.bin").st_mode & 0o777 != 0o600 else 0o640)
    (root / "new.txt").write_text("x")
    b, _ = snap(root)
    kinds = {x["label"]: x["change"] for x in compare(a, b)}
    assert kinds == {"root/a.txt": "metadata", "root/d/b.bin": "metadata", "root/new.txt": "added"}
    (root / "new.txt").unlink()
    (root / "a.txt").unlink()
    c, _ = snap(root)
    kinds = {x["label"]: x["change"] for x in compare(a, c)}
    assert kinds["root/a.txt"] == "missing"
    (root / "d" / "b.bin").write_bytes(b"short")
    d_, _ = snap(root)
    assert {x["label"]: x["change"] for x in compare(a, d_)}["root/d/b.bin"] == "content"


def test_size_only_difference_branch():
    from forensictriage.integrity import ManifestEntry
    e = ManifestEntry("l", "l", "root", 5, 1, 0o644, "m", "s1", "h")
    f = ManifestEntry("l", "l", "root", 6, 1, 0o644, "m", "s1", "h")
    assert compare(Manifest([e]), Manifest([f]))[0]["change"] == "size"


def test_manifest_round_trip_and_unreadable_files(tmp_path):
    root = tree(tmp_path)
    m = snapshot([("root/a.txt", "root", root / "a.txt"), ("root/gone", "root", root / "gone")], root)
    assert [e.label for e in m.entries] == ["root/a.txt"]
    assert m.skipped and "unreadable" in m.skipped[0]["reason"]
    again = Manifest.from_dict(json.loads(json.dumps(m.to_dict())))
    assert again.digest() == m.digest() and again.entries[0].rel == "a.txt"
    d = m.to_dict()
    assert d["files"] == 1 and d["bytes"] == 5 and d["digest_sha256"] == m.digest()


def test_digest_ignores_entry_order(tmp_path):
    root = tree(tmp_path)
    a, _ = snap(root)
    b = Manifest(list(reversed(a.entries)))
    assert a.digest() == b.digest()
