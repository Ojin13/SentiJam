from pathlib import Path

from jamtriage.checks import strings as strings_check
from jamtriage.checks.code import _pyinstaller_scope, scan_text
from jamtriage.checks.web import external_domains, scan_web_file
from jamtriage.filetypes import classify
from jamtriage.models import Finding, Severity
from jamtriage.rules import code_rules, custom_rules, web_rules
from jamtriage.scoring import lookup_findings, verdict

RULES = Path(__file__).resolve().parent.parent / "rules"


def test_classify_flags(tmp_path):
    p = tmp_path / "cover.png.exe"
    p.write_bytes(b"")
    assert "double-extension" in classify(p)[1]
    p = tmp_path / "game‮gpj.exe"
    p.write_bytes(b"")
    assert "rtlo-filename" in classify(p)[1]
    p = tmp_path / "level.dat"
    p.write_bytes(b"MZ" + b"\0" * 100)
    kind, tags = classify(p)
    assert kind == "pe" and "pe-disguised" in tags
    p = tmp_path / "run.vbs"
    p.write_bytes(b"x")
    assert "dangerous-script" in classify(p)[1]


def test_string_rules_ascii_and_utf16(tmp_path):
    rules = custom_rules(RULES)
    rx, lookup, overlap = strings_check.build_matcher(rules.string_rules)
    p = tmp_path / "bin.exe"
    p.write_bytes(b"\0" * 5000 + "https://discord.com/api/webhooks/1/x".encode("utf-16-le") + b"\0" * 10
                  + b"CRYPTUNPROTECTDATA")
    hits = strings_check.scan_file(p, rx, lookup, overlap, 1 << 20)
    assert {"exfil-discord-webhook", "api-cryptunprotectdata"} <= set(hits)


def test_string_rules_across_chunk_boundary(tmp_path, monkeypatch):
    monkeypatch.setattr(strings_check, "CHUNK", 64)
    rules = custom_rules(RULES)
    rx, lookup, overlap = strings_check.build_matcher(rules.string_rules)
    p = tmp_path / "b.bin"
    p.write_bytes(b"A" * 50 + b"api.telegram.org/bot123" + b"B" * 100)
    assert "exfil-telegram-bot" in strings_check.scan_file(p, rx, lookup, overlap, 1 << 20)


def test_engine_runtime_detection():
    rules = custom_rules(RULES)
    assert rules.is_engine_runtime("unpacked/game.zip/UnityPlayer.dll")
    assert rules.is_engine_runtime("unpacked/game.zip/Game_Data/Managed/UnityEngine.CoreModule.dll")
    assert not rules.is_engine_runtime("unpacked/game.zip/Game_Data/Managed/Assembly-CSharp.dll")
    assert rules.is_helper_exe("UnityCrashHandler64.exe")


def test_code_rules_per_language():
    cr = code_rules(RULES)
    cs = scan_text('var p = Process.Start("cmd.exe");\nvar d = ProtectedData.Unprotect(x, null, s);',
                   cr.languages["csharp"] + cr.shared)
    assert {"process-start", "protected-data-unprotect"} <= set(cs)
    gd = scan_text('OS.shell_open("https://itch.io")\nOS.shell_open(path)', cr.languages["gdscript"])
    assert gd["shell-open-nonweb"][1] == 2   # web link on line 1 is fine, line 2 is flagged
    py = scan_text("subprocess\nPopen\nbrowser_cookie3", cr.languages["python"], use_pyc=True)
    assert {"subprocess", "browser-cookie3"} <= set(py)
    js = scan_text('const cp = require("node:child_process")', cr.languages["javascript"])
    assert "child-process" in js
    clean = scan_text('func _ready():\n\tprint("hello")\n\tvar f = FileAccess.open("user://save.dat", FileAccess.READ)',
                      cr.languages["gdscript"] + cr.shared)
    assert clean == {}


def test_pyinstaller_scope():
    assert _pyinstaller_scope("unwrapped/pyinstaller/01/g.exe_extracted/pyi_rth_inspect.pyc") == "skip"
    assert _pyinstaller_scope("unwrapped/pyinstaller/01/g.exe_extracted/PYZ-00.pyz_extracted/subprocess.pyc") == "skip"
    assert _pyinstaller_scope("unwrapped/pyinstaller/01/g.exe_extracted/PYZ-00.pyz_extracted/pygame/x.pyc") == "third"
    assert _pyinstaller_scope("unwrapped/pyinstaller/01/g.exe_extracted/main.pyc") is None


def test_web_rules_each_fire_once():
    wr = web_rules(RULES)
    html = """<script src="https://evil.example.net/x.js"></script>
<input type='password'><a href="setup.exe">x</a>
<script>var a="stratum+tcp://p:1"; window.location = "https://phish.example.org/"; navigator.geolocation.getCurrentPosition(f);
eval(atob("YWxlcnQoMSk="));</script>"""
    ids = {r.id for r, *_ in scan_web_file(html, "html", wr)}
    assert ids == {"phishing-password", "download-push", "crypto-miner", "redirect-external", "permissions", "hidden-code"}
    assert external_domains(html, wr) == {"evil.example.net"}


def test_web_redirect_to_itch_is_fine():
    wr = web_rules(RULES)
    ids = {r.id for r, *_ in scan_web_file('window.location = "https://someone.itch.io/game";', "js", wr)}
    assert "redirect-external" not in ids
    assert wr.domain_class("cdn.jsdelivr.net") == "cdn"
    assert wr.domain_class("api.gameanalytics.com") == "service"
    assert wr.is_loader("unpacked/web.zip/Build/game.framework.js")


def f(sev):
    return Finding(rule="x", severity=Severity.parse(sev), title="t")


def test_verdict_rules():
    assert verdict([f("critical"), f("low")], True)[0] == "Disqualify"
    assert verdict([f("high")], True)[0] == "Review"
    assert verdict([f("medium")] * 3, False)[0] == "Review"
    assert verdict([f("medium")] * 2, True)[0] == "Web"
    assert verdict([f("medium")] * 2 + [f("info")], False)[0] == "Sandbox OK"
    v, reasons = verdict([f("high"), f("low")], False)
    assert reasons and all(r.severity == Severity.HIGH for r in reasons)


def test_lookup_findings():
    from jamtriage.models import FileRecord

    recs = [FileRecord(path="unpacked/g.zip/Game.exe", size=1, kind="pe", sha256="a" * 64),
            FileRecord(path="unpacked/g.zip/x.dll", size=1, kind="pe", sha256="b" * 64),
            FileRecord(path="unpacked/g.zip/y.dll", size=1, kind="pe", sha256="c" * 64)]
    cache = {
        "a" * 64: {"virustotal": {"found": True, "malicious": 2, "total": 70,
                                  "detections": [["X", "Trojan:Win32/Wacatac.B!ml"], ["Y", "Generic.ML"]]}},
        "b" * 64: {"malwarebazaar": {"found": True, "signature": "LummaStealer", "tags": ["lumma"]}},
        "c" * 64: {"virustotal": {"found": True, "malicious": 1, "total": 70, "label": "trojan.lumma/stealer",
                                  "detections": [["Z", "Trojan.Lumma"]]}},
    }
    out, _ = lookup_findings(recs, lambda s: cache.get(s), {}, ["godot"], {})
    by = {x.file: x for x in out}
    assert by["unpacked/g.zip/Game.exe"].severity == Severity.LOW          # generic ML hits on unsigned Godot
    assert by["unpacked/g.zip/x.dll"].severity == Severity.CRITICAL         # MalwareBazaar knows it
    assert by["unpacked/g.zip/y.dll"].severity == Severity.HIGH             # one engine names a stealer: Review
    out, _ = lookup_findings(recs[:1], lambda s: {"virustotal": {"found": False}}, {}, [], {})
    assert [x.rule for x in out] == ["lookup.unknown"]


def test_virustotal_severity_policy():
    from jamtriage.models import FileRecord
    from jamtriage.scoring import ML_SUFFIX

    def sev(vt, engines=("godot",)):
        rec = FileRecord(path="unpacked/g/Game.exe", size=1, kind="pe", sha256="d" * 64)
        out, _ = lookup_findings([rec], lambda s: {"virustotal": {"found": True, "total": 70, **vt}}, {},
                                 list(engines), {})
        return next(f.severity for f in out if f.file)

    ml = [["A", "Trojan:Win32/Wacatac.B!ml"], ["B", "W32.AIDetectMalware"], ["C", "Malicious.moderate.ml.score"]]
    real = [["A", "Trojan.GenericKD.1"], ["B", "Win32:MalwareX-gen [Trj]"], ["C", "Trojan.Agent.ABC"]]
    assert sev({"malicious": 3, "detections": ml}) == Severity.HIGH            # 3 ML-only verdicts: look, don't DQ
    assert sev({"malicious": 3, "detections": real}) == Severity.CRITICAL      # 3 real engines agree
    assert sev({"malicious": 2, "detections": [["A", "Trojan.Lumma.A"], ["B", "Win32/LummaStealer"]]}) \
        == Severity.CRITICAL                                                    # family named by 2 engines
    assert sev({"malicious": 1, "detections": [["A", "Trojan.Downloader.Gen"]]}) == Severity.MEDIUM
    assert sev({"malicious": 1, "detections": [["A", "Backdoor.AsyncRAT"]]}) == Severity.HIGH
    assert sev({"malicious": 12, "detections": ml * 4}) == Severity.CRITICAL   # overwhelming
    # "HTML.Phishing" is a real signature, not a machine-learning verdict (old regex matched "ml.")
    assert not ML_SUFFIX.search("HTML.Phishing.Gen") and not ML_SUFFIX.search("Trojan.Kai.A")
    assert ML_SUFFIX.search("Trojan:Win32/Wacatac.B!ml") and ML_SUFFIX.search("ML.Attribute.HighConfidence")


def test_metadefender_reputation_only_answer_is_unknown():
    from jamtriage.lookups.services import MetaDefender
    from jamtriage.models import FileRecord

    # What MetaDefender returns for a hash nobody ever uploaded: one engine's cloud reputation, no file data.
    never_seen = MetaDefender.parse({"file_info": {"sha256": "X"}, "scan_results": {
        "total_avs": 1, "total_detected_avs": 0, "scan_all_result_a": "No Threat Detected",
        "scan_details": {"Avira": {"scan_result_i": 0, "threat_found": ""}}}})
    assert never_seen["reputation_only"] is True
    rec = FileRecord(path="unpacked/g/Game.exe", size=1, kind="pe", sha256="e" * 64)
    out, summary = lookup_findings([rec], lambda s: {"metadefender": never_seen}, {}, [], {})
    assert summary["md"] == {} and any(f.rule == "lookup.unknown" for f in out)
    scanned = {"found": True, "detected": 0, "total": 21}
    out, summary = lookup_findings([rec], lambda s: {"metadefender": scanned}, {}, [], {})
    assert summary["md"] == {rec.path: "0/21"} and not any(f.rule == "lookup.unknown" for f in out)


def test_unknown_overlay_detection(tmp_path):
    from jamtriage.checks.unwrap import unknown_overlay

    exe = tmp_path / "game.exe"
    exe.write_bytes(b"MZ" + b"\0" * (200_000 - 2) + b"CPYARC02" + b"\1" * 3_000_000)
    size, share, head = unknown_overlay(exe, {"overlay_offset": 200_000})
    assert size == 3_000_008 and share > 0.9 and head.startswith(b"CPYARC02")
    assert unknown_overlay(exe, {"overlay_offset": None}) is None
    small = tmp_path / "small.exe"                       # a few KB of appended data: normal, not a payload
    small.write_bytes(b"MZ" + b"\0" * 5_000_000 + b"x" * 4096)
    assert unknown_overlay(small, {"overlay_offset": 5_000_002}) is None
    signed = tmp_path / "signed.exe"                     # the overlay is just a (big) Authenticode signature
    signed.write_bytes(b"MZ" + b"\0" * 1_000_000 + b"S" * 2_000_000)
    assert unknown_overlay(signed, {"overlay_offset": 1_000_002, "cert_offset": 1_000_002,
                                    "cert_size": 2_000_000}) is None


def test_file_reputation_lowers_only_heuristics_on_established_clean_files():
    from datetime import date

    from jamtriage.models import FileRecord
    from jamtriage.scoring import apply_reputation, established_clean

    today = date(2026, 11, 11)
    old_clean = {"found": True, "malicious": 0, "suspicious": 0, "total": 71, "first_seen": "2018-11-12"}
    assert established_clean(old_clean, today) == "2018-11-12"
    assert not established_clean({**old_clean, "first_seen": "2026-10-01"}, today)   # too new
    assert not established_clean({**old_clean, "total": 39}, today)                  # too few engines
    assert not established_clean({**old_clean, "malicious": 1}, today)               # any detection
    assert not established_clean({"found": False}, today)

    rec = FileRecord(path="x/StdUtils.dll", size=1, kind="pe", sha256="f" * 64)
    new = FileRecord(path="x/Game.exe", size=1, kind="pe", sha256="0" * 64)
    cache = {rec.sha256: {"virustotal": old_clean}, new.sha256: {"virustotal": {"found": False}}}
    fs = [Finding(rule="strings.api-cryptunprotectdata", severity=Severity.HIGH, title="t", file=rec.path,
                  source="strings"),
          Finding(rule="av.detection", severity=Severity.HIGH, title="t", file=rec.path, source="clamav"),
          Finding(rule="yara.x", severity=Severity.CRITICAL, title="t", file=rec.path, source="yara"),
          Finding(rule="pe.overlay_unscanned", severity=Severity.HIGH, title="t", file=rec.path, source="unwrap"),
          Finding(rule="strings.api-cryptunprotectdata", severity=Severity.HIGH, title="t", file=new.path,
                  source="strings")]
    out = apply_reputation(fs, [rec, new], cache.get, today)
    assert [f.severity for f in out] == [Severity.LOW, Severity.HIGH, Severity.CRITICAL, Severity.HIGH,
                                         Severity.HIGH]
    assert "known clean on VirusTotal since 2018-11-12" in out[0].detail


def test_capa_string_rules_ignore_harmless_words_and_packed_data():
    import json as _json

    from jamtriage.checks.capa import is_high, parse_capa, string_noise

    def rule(name, ns, captures):
        child = {"success": True, "node": {"type": "feature", "feature": {"type": "regex", "regex": "/x/i"}},
                 "children": [], "locations": [],
                 "captures": {t: [{"type": "file", "value": o} for o in offs] for t, offs in captures.items()}}
        miss = {"success": False, "node": {"type": "feature", "feature": {"type": "regex", "regex": "/y/"}},
                "children": [], "captures": {"nope": [{"type": "file", "value": 1}]}}
        tree = {"success": True, "node": {"type": "statement", "statement": {"type": "or"}}, "children": [child, miss]}
        return name, {"meta": {"namespace": ns}, "matches": [[{"type": "no address"}, tree]]}

    doc = {"rules": dict([
        rule("reference analysis tools strings", "anti-analysis", {"Friday": [60660]}),        # weekday table
        rule("reference cryptocurrency strings", "impact/cryptocurrency", {"Dash": [100]}),    # a dash move
        rule("reference anti-VM strings targeting Xen", "anti-analysis/anti-vm/vm-detection",
             {"XENO": [4_000_000]}),                                                           # inside the payload
        rule("reference analysis tools strings 2", "anti-analysis", {"x64dbg.exe": [500], "Friday": [9]}),
    ])}
    caps = {c["name"]: c for c in parse_capa(_json.dumps(doc))}
    assert caps["reference analysis tools strings"]["evidence"] == [("Friday", [60660])]      # failed branch ignored
    assert string_noise(caps["reference analysis tools strings"], None)[0]
    assert string_noise(caps["reference cryptocurrency strings"], None)[0]
    xen = caps["reference anti-VM strings targeting Xen"]
    assert is_high(xen) and string_noise(xen, overlay_offset=224_768) == (True, "matched 'XENO' (in appended data)")
    assert not string_noise(xen, overlay_offset=None)[0]                  # no overlay: a real match
    real, shown = string_noise(caps["reference analysis tools strings 2"], None)
    assert not real and "'x64dbg.exe'" in shown                         # a real tool name keeps the finding
