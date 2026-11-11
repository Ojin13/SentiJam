import io
import os
import stat
import tarfile
import zipfile

from jamtriage.fixtures import EICAR, EICAR_SHA256, mark_zip_encrypted, zip_bytes
from jamtriage.hashing import hash_file
from jamtriage.unpack import (Budget, Limits, parse_7z_slt, safe_member_name, unpack_recursive, unpack_tar,
                              unpack_zip, zip_is_encrypted)


def rules(result):
    return [f.rule for f in result.findings]


def test_safe_member_name():
    assert safe_member_name("a/b/c.txt") == "a/b/c.txt"
    assert safe_member_name("./a//b") == "a/b"
    assert safe_member_name("a\\b.txt") == "a/b.txt"
    for bad in ("../x", "a/../../x", "/etc/passwd", "C:\\Windows\\x", "c:x", "\\\\server\\share\\x", "a\x00b", "", ".."):
        assert safe_member_name(bad) is None, bad


def test_zip_slip_blocked(tmp_path):
    arc = tmp_path / "slip.zip"
    arc.write_bytes(zip_bytes({"ok.txt": b"fine", "../../evil.txt": b"x", "/abs.txt": b"x", "a/../../b.txt": b"x"}))
    dest = tmp_path / "out" / "slip"
    res = unpack_zip(arc, dest, Budget(Limits()), "slip.zip")
    assert "archive.path_traversal" in rules(res)
    assert [p.name for p in res.extracted] == ["ok.txt"]
    assert not list(tmp_path.rglob("evil.txt")) and not list(tmp_path.rglob("abs.txt"))


def test_zip_symlink_blocked(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, "/etc/passwd")
    arc = tmp_path / "l.zip"
    arc.write_bytes(buf.getvalue())
    res = unpack_zip(arc, tmp_path / "o", Budget(Limits()), "l.zip")
    assert "archive.link_blocked" in rules(res)
    assert res.extracted == []


def test_encrypted_zip_detected(tmp_path):
    arc = tmp_path / "enc.zip"
    arc.write_bytes(mark_zip_encrypted(zip_bytes({"a.txt": b"hello"}, zipfile.ZIP_STORED)))
    assert zip_is_encrypted(arc)
    res = unpack_zip(arc, tmp_path / "o", Budget(Limits()), "enc.zip")
    assert res.encrypted
    f = next(f for f in res.findings if f.rule == "archive.encrypted")
    assert f.severity.label == "high"


def test_zip_bomb_ratio_limit(tmp_path):
    arc = tmp_path / "bomb.zip"
    arc.write_bytes(zip_bytes({"zeros.bin": b"\0" * (8 * 1024 * 1024)}))
    # would blow the (small) byte budget: refused, and refusal is High because nothing was scanned
    res = unpack_zip(arc, tmp_path / "o", Budget(Limits(max_ratio=100, max_total_bytes=4 * 1024 * 1024)), "bomb.zip")
    assert "archive.limit" in rules(res)
    assert all(f.severity.name == "HIGH" for f in res.findings if f.rule == "archive.limit")
    assert res.extracted == []


def test_padded_payload_is_extracted_not_skipped(tmp_path):
    """Malware padded with zeros to dodge scanners: high ratio but fits the budget, so we extract and scan it."""
    arc = tmp_path / "padded.zip"
    arc.write_bytes(zip_bytes({"game.exe": b"MZ" + b"\0" * (8 * 1024 * 1024)}))
    res = unpack_zip(arc, tmp_path / "o", Budget(Limits(max_ratio=100)), "padded.zip")
    assert "archive.high_ratio" in rules(res) and "archive.limit" not in rules(res)
    assert len(res.extracted) == 1 and res.extracted[0].stat().st_size == 8 * 1024 * 1024 + 2


def test_small_compressible_files_are_fine(tmp_path):
    arc = tmp_path / "ok.zip"
    arc.write_bytes(zip_bytes({"tiny.txt": b"\0" * 50_000}))  # high ratio but under 1 MiB
    res = unpack_zip(arc, tmp_path / "o", Budget(Limits(max_ratio=100)), "ok.zip")
    assert res.findings == [] and len(res.extracted) == 1


def test_file_count_and_size_limits(tmp_path):
    arc = tmp_path / "many.zip"
    arc.write_bytes(zip_bytes({f"f{i}.txt": b"x" * 10 for i in range(20)}))
    budget = Budget(Limits(max_files=5))
    res = unpack_zip(arc, tmp_path / "o", budget, "many.zip")
    assert len(res.extracted) == 5 and "archive.limit" in rules(res)
    budget = Budget(Limits(max_total_bytes=55))
    res = unpack_zip(arc, tmp_path / "o2", budget, "many.zip")
    assert len(res.extracted) == 5 and "archive.limit" in rules(res)


def test_extracted_files_are_not_executable(tmp_path):
    arc = tmp_path / "x.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("run.sh")
        info.external_attr = (stat.S_IFREG | 0o755) << 16
        zf.writestr(info, "#!/bin/sh\necho hi\n")
    arc.write_bytes(buf.getvalue())
    res = unpack_zip(arc, tmp_path / "o", Budget(Limits()), "x.zip")
    mode = os.stat(res.extracted[0]).st_mode
    assert not mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def test_nested_archives_and_depth(tmp_path):
    inner2 = zip_bytes({"deep.txt": b"deep"})
    inner = zip_bytes({"inner2.zip": inner2, "mid.txt": b"mid"})
    arc = tmp_path / "outer.zip"
    arc.write_bytes(zip_bytes({"inner.zip": inner, "top.txt": b"top"}))
    res = unpack_recursive(arc, tmp_path / "o", Budget(Limits(max_depth=2)), "outer.zip")
    names = sorted(p.name for p in res.extracted)
    assert "mid.txt" in names and "deep.txt" not in names
    assert rules(res).count("archive.nested") == 2
    assert any(f.rule == "archive.limit" and "depth" in f.detail for f in res.findings)


def test_tar_traversal_and_links(tmp_path):
    arc = tmp_path / "t.tar.gz"
    with tarfile.open(arc, "w:gz") as tf:
        for name, data in (("good.txt", b"ok"), ("../evil.txt", b"bad")):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        ti = tarfile.TarInfo("link")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "/etc/passwd"
        tf.addfile(ti)
    res = unpack_tar(arc, tmp_path / "o", Budget(Limits()), "t.tar.gz")
    assert [p.name for p in res.extracted] == ["good.txt"]
    assert {"archive.path_traversal", "archive.link_blocked"} <= set(rules(res))
    assert not list(tmp_path.rglob("evil.txt"))


def test_parse_7z_slt():
    text = """7-Zip 23.01
Listing archive: a.7z
--
Path = a.7z
Type = 7z
----------
Path = game/Game.exe
Size = 1000
Packed Size = 500
Attributes = A
Encrypted = -

Path = secret.txt
Size = 10
Encrypted = +
"""
    members, hdr = parse_7z_slt(text)
    assert not hdr
    assert [m["Path"] for m in members] == ["game/Game.exe", "secret.txt"]
    assert members[1]["Encrypted"] == "+"
    _, hdr = parse_7z_slt("ERROR: a.7z : Can not open encrypted archive. Wrong password?")
    assert hdr


def test_hashes(tmp_path):
    p = tmp_path / "eicar.com"
    p.write_bytes(EICAR)
    h = hash_file(p)
    assert h["sha256"] == EICAR_SHA256
    assert h["md5"] == "44d88612fea8a8f36de82e1278abb02f"
