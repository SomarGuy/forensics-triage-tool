import hashlib

from forensictriage.hashing import Digests, HashList, hash_bytes, hash_file


def test_hash_file_matches_hashlib_and_is_single_pass(tmp_path):
    data = b"forensics" * 400_000            # larger than one read chunk
    p = tmp_path / "f.bin"
    p.write_bytes(data)
    d = hash_file(p)
    assert d.md5 == hashlib.md5(data).hexdigest()
    assert d.sha1 == hashlib.sha1(data).hexdigest()
    assert d.sha256 == hashlib.sha256(data).hexdigest()
    assert d.size == len(data)
    assert hash_bytes(data) == d


def test_empty_file(tmp_path):
    p = tmp_path / "empty"
    p.write_bytes(b"")
    assert hash_file(p).sha256 == hashlib.sha256(b"").hexdigest()


def test_hash_file_does_not_modify_the_file(tmp_path):
    p = tmp_path / "x"
    p.write_bytes(b"abc")
    before = (p.stat().st_size, p.stat().st_mtime_ns, p.read_bytes())
    hash_file(p)
    assert (p.stat().st_size, p.stat().st_mtime_ns, p.read_bytes()) == before


def test_hashlist_loads_all_three_algorithms_and_comments(tmp_path):
    d = hash_bytes(b"evil")
    lst = tmp_path / "bad.txt"
    lst.write_text(f"# comment\n\n{d.md5}  md5 label\n{d.sha1} *sha1.exe\n{d.sha256.upper()}\tsha256 label\nnot-a-hash  oops\nabc123  too short\n")
    h = HashList()
    assert h.load_file("known_bad", lst) == 3
    assert h.skipped == 2
    assert h.lookup(d).category == "known_bad"
    assert h.lookup_hex(d.sha1).label == "sha1.exe"
    assert h.lookup_hex(d.sha256).algorithm == "sha256"
    assert len(h) == 3


def test_no_match_and_bad_lookup():
    h = HashList()
    assert h.lookup(hash_bytes(b"x")) is None
    assert h.lookup_hex("zz") is None
    assert h.lookup_hex("a" * 32) is None


def test_known_bad_wins_over_known_good():
    d = hash_bytes(b"dual")
    h = HashList()
    h.add("known_bad", d.sha256, "bad")
    h.add("known_good", d.sha256, "good")
    assert h.lookup(d).category == "known_bad"
    h2 = HashList()                                 # order must not matter
    h2.add("known_good", d.sha256, "good")
    h2.add("known_bad", d.sha256, "bad")
    assert h2.lookup(d).category == "known_bad"


def test_lookup_matches_on_any_algorithm_and_prefers_bad():
    d = hash_bytes(b"multi")
    h = HashList()
    h.add("known_good", d.md5, "good by md5")
    h.add("known_bad", d.sha1, "bad by sha1")
    assert h.lookup(d).label == "bad by sha1"
    only_good = HashList()
    only_good.add("known_good", d.md5, "g")
    assert only_good.lookup(d).category == "known_good"


def test_default_label_is_hash_prefix():
    h = HashList()
    h.add("known_bad", "a" * 64)
    assert h.lookup_hex("a" * 64).label == "a" * 12
