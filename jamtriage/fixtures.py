"""Harmless fixtures for `triage selftest` and the unit tests.

Nothing here is malware. EICAR is the industry-standard antivirus test string; it is assembled at
runtime so this source file itself doesn't trip scanners.
"""
from __future__ import annotations

import io
import struct
import zipfile
from pathlib import Path

from .checks.unwrap import build_asar

EICAR = (r"X5O!P%@AP[4\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-" + "ANTIVIRUS-TEST-FILE!$H+H*").encode("ascii")
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def zip_bytes(members: dict[str, bytes], compression=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=compression) as zf:
        for name, data in members.items():
            zf.writestr(zipfile.ZipInfo(name, date_time=(2026, 11, 1, 0, 0, 0)), data, compress_type=compression)
    return buf.getvalue()


def mark_zip_encrypted(data: bytes) -> bytes:
    """Set the 'encrypted' flag bit on every member (local headers and central directory).

    Detection only reads this flag, so the fixture behaves exactly like a password-protected zip
    without needing an encryption library.
    """
    b = bytearray(data)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            off = info.header_offset
            assert b[off:off + 4] == b"PK\x03\x04"
            flags = struct.unpack_from("<H", b, off + 6)[0] | 0x1
            struct.pack_into("<H", b, off + 6, flags)
        pos = zf.start_dir
    while True:
        pos = b.find(b"PK\x01\x02", pos)
        if pos < 0:
            break
        flags = struct.unpack_from("<H", b, pos + 8)[0] | 0x1
        struct.pack_into("<H", b, pos + 8, flags)
        pos += 4
    return bytes(b)


FAKE_STEALER_JS = b"""// harmless self-test fixture: contains strings only, does nothing
const target = "C:\\\\Users\\\\x\\\\AppData\\\\Local\\\\Google\\\\Chrome\\\\User Data\\\\Default\\\\Login Data";
const hook = "https://discord.com/api/webhooks/000000000000000000/selftest-not-a-real-token";
const api = "CryptUnprotectData";
"""
FAKE_STEALER_TXT = (b"self-test fixture\n\\Google\\Chrome\\User Data\\Default\\Login Data\n"
                    b"https://discord.com/api/webhooks/000/selftest\nCryptUnprotectData\n")
FAKE_ELECTRON_MAIN = b"""// harmless self-test fixture
const { exec } = require("child_process");
const fs = require("fs");
const p = process.env.LOCALAPPDATA + "\\\\Google\\\\Chrome\\\\User Data\\\\Local State";
function never() { fs.readFileSync(p); exec("echo selftest"); }
module.exports = { never };
"""
FAKE_GDSCRIPT = b"""extends Node
# harmless self-test fixture
func _ready():
\tvar appdata = OS.get_environment("APPDATA")
\tvar out = []
\tif false:
\t\tOS.execute("cmd.exe", ["/c", "echo", appdata], out)
"""
BAD_WEB_INDEX = b"""<!doctype html>
<html><head><title>selftest web build</title>
<script src="https://evil-cdn.example.net/loader.js"></script>
</head><body>
<form><input type="password" name="pw"></form>
<a href="setup.exe">Download the full version</a>
<script>
  var pool = "stratum+tcp://pool.example.com:3333";
  function go() { window.location = "https://phish.example.org/login"; }
</script>
</body></html>
"""


def build_fixtures(builds: Path) -> dict[str, Path]:
    """Create one folder per fixture under `builds` (manual layout). Returns {name: folder}."""
    out = {}

    def entry(name: str) -> Path:
        d = builds / name
        d.mkdir(parents=True, exist_ok=True)
        out[name] = d
        return d

    (entry("eicar-plain") / "eicar.com").write_bytes(EICAR)
    (entry("eicar-zipped") / "eicar.zip").write_bytes(zip_bytes({"eicar.com": EICAR}))
    (entry("zip-slip") / "game.zip").write_bytes(zip_bytes({"readme.txt": b"hello\n", "../../evil.txt": b"escaped!\n"}))
    (entry("encrypted-zip") / "game.zip").write_bytes(
        mark_zip_encrypted(zip_bytes({"game.exe": b"not really an exe\n", "data.txt": b"x" * 100}, zipfile.ZIP_STORED)))
    (entry("zip-bomb-lite") / "bomb.zip").write_bytes(zip_bytes({"zeros.bin": b"\0" * (20 * 1024 * 1024)}))
    d = entry("fake-stealer")
    (d / "notes.txt").write_bytes(FAKE_STEALER_TXT)
    (d / "steal.js").write_bytes(FAKE_STEALER_JS)
    (entry("double-extension") / "cover.png.exe").write_bytes(b"")
    d = entry("fake-electron") / "resources"
    d.mkdir(parents=True, exist_ok=True)
    build_asar({"package.json": b'{"name":"selftest","main":"main.js"}', "main.js": FAKE_ELECTRON_MAIN}, d / "app.asar")
    d = entry("fake-godot-script")
    (d / "player.gd").write_bytes(FAKE_GDSCRIPT)
    (entry("bad-web-build") / "web.zip").write_bytes(zip_bytes({"index.html": BAD_WEB_INDEX}))
    d = entry("clean-game")
    (d / "readme.txt").write_bytes(b"A tiny text adventure. Open story.txt and read along.\n")
    (d / "story.txt").write_bytes(b"You are in a room. There is a door. The end.\n")
    return out


def tiny_pe(section_data: bytes = b"", overlay: bytes = b"") -> bytes:
    """A minimal, valid (but non-functional) 32-bit PE that pefile parses; for tests only, never run."""
    import struct as _s

    body = (b"\xc3" + section_data).ljust(0x200, b"\0")
    raw = (len(body) + 0x1FF) // 0x200 * 0x200
    body = body.ljust(raw, b"\0")
    dos = b"MZ" + b"\0" * 0x3A + _s.pack("<I", 0x40)
    fh = _s.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    opt = _s.pack("<HBBIIIIIII", 0x10B, 0, 0, raw, 0, 0, 0x1000, 0x1000, 0x1000, 0x400000)
    opt += _s.pack("<IIHHHHHHIIIIHHIIIIII", 0x1000, 0x200, 4, 0, 0, 0, 4, 0, 0,
                   0x1000 + (raw + 0xFFF) // 0x1000 * 0x1000, 0x200, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += b"\0" * (16 * 8)
    sec = _s.pack("<8sIIIIIIHHI", b".text", raw, 0x1000, raw, 0x200, 0, 0, 0, 0, 0x60000020)
    header = (dos + b"PE\0\0" + fh + opt + sec).ljust(0x200, b"\0")
    return header + body + overlay
