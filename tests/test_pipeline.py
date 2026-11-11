import json
import shutil
from pathlib import Path

import pytest

from jamtriage.checks.antivirus import parse_clamscan, parse_mpcmdrun
from jamtriage.checks.capa import is_high, parse_capa
from jamtriage.checks.diec import parse_diec
from jamtriage.checks.unwrap import AsarError, build_asar, extract_asar
from jamtriage.entries import discover_entries
from jamtriage.fixtures import build_fixtures, zip_bytes
from jamtriage.pipeline import Pipeline, local_path
from jamtriage.report import build_reports, read_user_columns
from jamtriage.selftest import evaluate


def test_discover_itch_dl_and_manual_layouts(tmp_path):
    b = tmp_path / "builds"
    g = b / "alice" / "neon-drift"
    (g / "files").mkdir(parents=True)
    (g / "files" / "neon.zip").write_bytes(b"PK")
    (g / "metadata.json").write_text(json.dumps({"title": "Neon Drift", "author": "alice",
                                                 "extra": {"made_with": {"Godot": "x"}}}))
    (g / "screenshots").mkdir()
    (g / "screenshots" / "a.png").write_bytes(b"x")
    m = b / "paid-entry"
    m.mkdir()
    (m / "game.zip").write_bytes(b"PK")
    entries = {e.slug: e for e in discover_entries(b)}
    assert set(entries) == {"alice--neon-drift", "paid-entry"}
    e = entries["alice--neon-drift"]
    assert e.title == "Neon Drift" and e.claimed_engine == "Godot"
    assert [p.name for p in e.build_files()] == ["neon.zip"]


def test_asar_roundtrip_and_traversal(tmp_path):
    a = tmp_path / "app.asar"
    build_asar({"main.js": b"console.log(1)", "lib/x.js": b"x", "../escape.js": b"bad"}, a)
    out = extract_asar(a, tmp_path / "o")
    assert sorted(p.relative_to(tmp_path / "o").as_posix() for p in out) == ["lib/x.js", "main.js"]
    assert not list(tmp_path.rglob("escape.js"))
    bad = tmp_path / "bad.asar"
    bad.write_bytes(b"not an asar at all")
    with pytest.raises(AsarError):
        extract_asar(bad, tmp_path / "o2")


def test_full_pipeline_on_fixtures(cfg):
    build_fixtures(cfg.builds_dir)
    pipe = Pipeline(cfg)
    results = {r["slug"]: r for r in pipe.analyze(show_tools=False)}
    checks = evaluate(results, cfg.data_dir, av_available=False, vt_enabled=False, cache=None)
    failed = [c for c in checks if c.status == "fail"]
    assert not failed, failed
    assert results["clean-game"]["verdict"] == "Sandbox OK"
    assert results["bad-web-build"]["has_web"]
    # The detail of external-code findings names the domain.
    ext = next(f for f in results["bad-web-build"]["findings"] if f["rule"] == "web.external_code")
    assert ext["detail"] == "evil-cdn.example.net"


def test_rerun_reuses_saved_results_and_report_keeps_user_columns(cfg):
    build_fixtures(cfg.builds_dir)
    pipe = Pipeline(cfg)
    pipe.analyze(show_tools=False)
    first = local_path(cfg, "clean-game").read_text()
    pipe.analyze(show_tools=False)
    assert local_path(cfg, "clean-game").read_text() == first   # unchanged entry was not re-analysed

    paths = build_reports(cfg)
    from openpyxl import load_workbook
    wb = load_workbook(paths["xlsx"])
    ws = wb["Entries"]
    header = [c.value for c in ws[1]]
    for row in ws.iter_rows(min_row=2):
        if row[0].value == "clean-game":
            row[header.index("final verdict")].value = "Sandbox OK"
            row[header.index("notes")].value = "checked by hand"
            row[header.index("public upload consent")].value = "yes"
    wb.save(paths["xlsx"])
    build_reports(cfg)
    user = read_user_columns(paths["xlsx"])
    assert user["clean-game"] == {"final verdict": "Sandbox OK", "public upload consent": "yes",
                                  "notes": "checked by hand"}
    manifest = paths["manifest"].read_text().splitlines()
    assert manifest[0] == "entry,file,size,sha256" and len(manifest) > 5


def test_changed_build_is_reanalysed(cfg):
    d = cfg.builds_dir / "g"
    d.mkdir(parents=True)
    (d / "game.zip").write_bytes(zip_bytes({"readme.txt": b"hi"}))
    pipe = Pipeline(cfg)
    r1 = pipe.analyze(show_tools=False)[0]
    assert r1["verdict"] == "Sandbox OK"
    (d / "game.zip").write_bytes(zip_bytes({"readme.txt": b"hi", "run.vbs": b"x"}))
    r2 = pipe.analyze(show_tools=False)[0]
    assert r2["verdict"] == "Review"


def test_html_report_escapes_submission_text(cfg):
    d = cfg.builds_dir / "xss"
    d.mkdir(parents=True)
    (d / "<img src=x onerror=alert(1)>.png.exe").write_bytes(b"")
    Pipeline(cfg).analyze(show_tools=False)
    html = build_reports(cfg)["html"].read_text()
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_dashboard_status_endpoint(cfg):
    from fastapi.testclient import TestClient

    from jamtriage.dashboard import create_app

    build_fixtures(cfg.builds_dir)
    Pipeline(cfg).analyze(show_tools=False)
    client = TestClient(create_app(cfg))
    s = client.get("/api/status").json()
    assert s["state"] == "done" and s["entries"]["total"] == 11 and s["entries"]["done"] == 11
    assert s["verdicts"]["review"] >= 5 and s["quota"]["virustotal"]["enabled"] is False
    assert any(f["entry"] == "fake-stealer" for f in s["flagged"])
    page = client.get("/")
    assert page.status_code == 200 and "innerHTML" not in page.text.split("<script>")[1].replace("never innerHTML", "")


def test_dashboard_unified_static_and_sandbox(cfg):
    import json

    from jamtriage.dashboard import build_status
    from jamtriage.pipeline import result_path
    from jamtriage.state import State

    build_fixtures(cfg.builds_dir)
    Pipeline(cfg).analyze(show_tools=False)
    st = State(cfg.state_db)
    s = build_status(cfg, st)
    assert len(s["table"]) == 11
    assert s["sandbox"]["virustotal"]["not_started"] == 11 and s["sandbox"]["hybrid"]["total"] == 11
    assert "entries" not in s["sandbox"]["hybrid"]           # per-entry detail lives in the table only
    clean = next(r for r in s["table"] if r["verdict"] == "Sandbox OK")
    # A sandbox result arrives for the clean entry: High from Hybrid Analysis, VT still waiting.
    p = result_path(cfg, clean["entry"])
    data = json.loads(p.read_text())
    data["findings"].append({"rule": "detonation.malicious", "severity": "high", "title": "malicious",
                             "source": "hybrid-sandbox"})
    data.setdefault("info", {}).setdefault("sandbox", {})["hybrid"] = {"threat_score": 85}
    p.write_text(json.dumps(data))
    st.sandbox_set(clean["entry"], "hybrid", status="collected", attempts=2)
    st.sandbox_set(clean["entry"], "virustotal", status="waiting", attempts=1)
    st.sandbox_set("fake-stealer", "hybrid", status="skipped", note="no consent")
    s = build_status(cfg, st)
    hy, vt = s["sandbox"]["hybrid"], s["sandbox"]["virustotal"]
    assert (hy["collected"], hy["skipped"], hy["not_started"], hy["flagged"]) == (1, 1, 9, 1)
    assert (vt["running"], vt["not_started"]) == (1, 10)
    row = next(r for r in s["table"] if r["entry"] == clean["entry"])
    assert row["hybrid"]["status"] == "collected" and row["hybrid"]["worst"] == "high"
    assert row["hybrid"]["threat_score"] == 85 and row["virustotal"]["status"] == "running"
    assert row["static"]["worst"] in ("", "low")          # the static layer stays as it was
    stealer = next(r for r in s["table"] if r["entry"] == "fake-stealer")
    assert stealer["hybrid"]["detail"] == "no consent" and stealer["static"]["worst"] in ("high", "critical")


def test_tool_output_parsers():
    assert parse_clamscan("/x/eicar.com: Eicar-Signature FOUND\n/x/ok: OK") == [("/x/eicar.com", "Eicar-Signature")]
    mp = """Scan starting...
Scan finished.
Scanning C:\\data found 1 threats.
<===========================LIST OF DETECTED THREATS==========================>
----------------------------- Threat information ------------------------------
Threat                  : Virus:DOS/EICAR_Test_File
Resources               : 1 total
    file                : C:\\data\\eicar.com
-------------------------------------------------------------------------------"""
    assert parse_mpcmdrun(mp) == [("C:\\data\\eicar.com", "Virus:DOS/EICAR_Test_File")]
    diec = '{"detects":[{"filetype":"PE64","values":[{"type":"Packer","name":"UPX","version":"4.0","string":"Packer: UPX(4.0)"},{"type":"Installer","name":"Nullsoft Scriptable Install System","version":"","string":"Installer: NSIS"}]}]}'
    assert [d["type"] for d in parse_diec(diec)] == ["Packer", "Installer"]
    capa = json.dumps({"rules": {
        "gather chrome based browser login information": {"meta": {"namespace": "collection/browser"}},
        "create process on Windows": {"meta": {"namespace": "host-interaction/process/create"}},
        "contain loop": {"meta": {"namespace": "internal", "lib": True}}}})
    caps = parse_capa(capa)
    assert len(caps) == 2 and [c["name"] for c in caps if is_high(c)] == ["gather chrome based browser login information"]


RIDER = Path("/Applications/Rider.app/Contents/tools/profiler/Reporter.exe")


@pytest.mark.skipif(not RIDER.exists(), reason="no sample signed PE on this machine")
def test_pe_inspection_on_real_signed_exe(cfg, tmp_path):
    d = cfg.builds_dir / "signed"
    d.mkdir(parents=True)
    shutil.copyfile(RIDER, d / "Reporter.exe")
    r = Pipeline(cfg).analyze(show_tools=False)[0]
    sig = r["info"]["signatures"]["builds/Reporter.exe"]
    assert sig["status"] in ("ok", "invalid", "unknown")
    assert r["info"]["main_exe"] == "builds/Reporter.exe"
    assert "builds/Reporter.exe" in r["info"]["pe"]


def test_clamav_batch_is_one_scan_and_maps_hits_to_entries(cfg, monkeypatch, tmp_path):
    import subprocess

    from jamtriage.checks import antivirus
    from jamtriage.tools import ToolStatus

    cfg.raw["antivirus"]["enabled"] = True
    build_fixtures(cfg.builds_dir)
    calls = []

    def fake_run_tool(cmd, timeout, cwd=None):
        calls.append(cmd)
        listed = Path(next(c for c in cmd if c.startswith("--file-list=")).split("=", 1)[1]).read_text().splitlines()
        out = [f"{p}/eicar.com: Eicar-Test-Signature FOUND" for p in listed if p.endswith("builds/eicar-plain")]
        return subprocess.CompletedProcess(cmd, 1 if out else 0, "\n".join(out), "")

    monkeypatch.setattr(antivirus, "run_tool", fake_run_tool)
    pipe = Pipeline(cfg)
    fake = tmp_path / "clamscan"
    fake.write_text("#!/bin/sh\n")
    pipe.tools["clamav"] = ToolStatus("clamav", "available", str(fake))
    results = {r["slug"]: r for r in pipe.analyze(show_tools=False)}
    assert len(calls) == 1                                   # one clamscan for all 11 entries
    assert [f["rule"] for f in results["eicar-plain"]["findings"]].count("av.detection") == 1
    assert results["eicar-plain"]["checks"]["clamav"] == "ok"
    assert results["clean-game"]["checks"]["clamav"] == "ok"
    assert not any(f["rule"] == "av.detection" for f in results["clean-game"]["findings"])


def test_capa_stderr_flags_ignore_paths():
    from jamtriage.checks.capa import capa_stderr_flags

    err = ("ERROR    capa: Input file                                            main.py:561\n"
           "         '/x/data/unpacked/g/game.zip/game.exe' is not a              \n"
           "         valid PE file: 'Invalid NT Headers signature.'\n")
    packed, limited = capa_stderr_flags(err)
    assert not packed and "not a valid PE file" in limited
    packed, _ = capa_stderr_flags("WARNING capa: This sample appears to be\n   packed.")
    assert packed


def test_independent_sources_counts_vendors_not_rules():
    from jamtriage.scoring import independent_sources

    def f(rule, sev, source):
        return {"rule": rule, "severity": sev, "source": source}

    # Three of our own heuristics = one source; VT lookup + VT sandbox are separate; coverage and Low don't count.
    found = [f("strings.discord-webhook", "high", "strings"), f("code.eval", "medium", "code"),
             f("pe.packed", "medium", "pe"), f("vt.named", "high", "virustotal"),
             f("detonation.malicious", "high", "virustotal-sandbox"), f("detonation.x", "high", "virustotal-behaviour"),
             f("hybrid", "medium", "hybrid-sandbox"), f("archive.unreadable", "high", "unwrap"),
             f("analysis.error", "high", "yara"), f("md.low", "low", "metadefender"),
             f("archive.encrypted", "high", "inventory"), f("av.vanished", "high", "hash"),
             f("clam", "critical", "clamav"), f("mp", "critical", "mdatp"), f("def", "critical", "defender")]
    assert independent_sources(found) == ["ClamAV", "Hybrid Analysis sandbox", "Microsoft Defender",
                                          "VirusTotal engines", "VirusTotal sandbox", "jam-triage rules",
                                          "local antivirus"]
    assert independent_sources([f("x", "low", "yara"), f("lookups.pending", "medium", "lookups")]) == []


def test_sources_in_results_report_and_dashboard(cfg):
    from jamtriage.dashboard import build_status
    from jamtriage.report import load_results
    from jamtriage.state import State

    build_fixtures(cfg.builds_dir)
    Pipeline(cfg).analyze(show_tools=False)
    results = {r["slug"]: r for r in load_results(cfg)}
    assert results["fake-stealer"]["sources"]                     # flagged by at least one source
    assert all(isinstance(r["sources"], list) for r in results.values())
    html = build_reports(cfg)["html"].read_text()
    assert "Independent sources that flagged it" in html
    s = build_status(cfg, State(cfg.state_db))
    row = next(r for r in s["table"] if r["entry"] == "fake-stealer")
    assert row["sources"] == results["fake-stealer"]["sources"]
    for slug, r in results.items():                              # nothing at Medium+ -> no source flagged it
        c = r["counts"]
        if not (c["critical"] or c["high"] or c["medium"]):
            assert r["sources"] == [], slug


def test_itchdl_shim_skips_unknown_infobox_rows():
    import pytest
    pytest.importorskip("itch_dl")
    from bs4 import BeautifulSoup
    from itch_dl import infobox

    import jamtriage.itchdl_shim  # noqa: F401  patches itch-dl on import

    html = ("<div><table><tr><td>Jams</td><td><a href='j'>Some jam</a></td></tr>"
            "<tr><td>Platforms</td><td><a href='w'>Windows</a></td></tr></table></div>")
    assert infobox.parse_infobox(BeautifulSoup(html, "html.parser")) == {"platforms": ["Windows"]}


def test_run_steps_recorded_and_shown(cfg):
    from jamtriage.dashboard import build_status, lookup_progress, run_steps
    from jamtriage.state import State

    build_fixtures(cfg.builds_dir)
    Pipeline(cfg).analyze(show_tools=False)
    s = build_status(cfg, State(cfg.state_db))
    steps = {st["key"]: st for st in s["steps"]}
    assert list(steps) == ["static", "clamav", "lookups", "score", "sandbox"]
    assert steps["static"]["state"] == "done" and steps["score"]["state"] == "done"
    assert steps["sandbox"]["state"] == "skipped" and "--sandbox" in steps["sandbox"]["detail"]
    assert steps["lookups"]["state"] == "skipped"                 # conftest disables the lookups
    assert all(st["state"] != "running" for st in s["steps"])
    # A run from before steps were recorded, sitting in the lookup wait:
    old = run_steps({"state": "running"}, {"stage": "hash lookups"}, done=9, total=9)
    assert [st["state"] for st in old] == ["done", "done", "running", "pending", "skipped"]
    old_done = run_steps({"state": "done"}, {}, done=9, total=9)
    assert [st["state"] for st in old_done] == ["done", "done", "done", "done", "skipped"]
    detail, eta = lookup_progress({
        "virustotal": {"enabled": True, "pending": 8, "requests_per_minute": 4.0, "next_request_in": 5,
                       "budget": 480, "used_today": 71},
        "malwarebazaar": {"enabled": True, "pending": 0},
        "metadefender": {"enabled": False, "pending": 3}})
    assert detail == "VirusTotal 8 left (~2 min at 4/min) · MalwareBazaar done" and eta == 125
    spent, _ = lookup_progress({"virustotal": {"enabled": True, "pending": 3, "requests_per_minute": 4.0,
                                               "budget": 10, "used_today": 10}})
    assert "budget used up" in spent


def test_tool_timeout_kills_child_processes_too(tmp_path):
    """A launcher (like the standalone capa) starts a worker; a timeout must stop the worker as well."""
    import os
    import sys
    import time

    import pytest

    from jamtriage.checks import ToolError, run_tool

    if sys.platform == "win32":
        pytest.skip("POSIX process groups")
    pidfile = tmp_path / "worker.pid"
    launcher = tmp_path / "launcher.py"
    launcher.write_text(
        "import subprocess, sys, time\n"
        "w = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"open({str(pidfile)!r}, 'w').write(str(w.pid))\n"
        "time.sleep(60)\n")
    with pytest.raises(ToolError, match="timed out"):
        run_tool([sys.executable, str(launcher)], timeout=2)
    worker = int(pidfile.read_text())
    for _ in range(50):                      # the kill is immediate; allow the OS a moment to reap
        try:
            os.kill(worker, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        os.kill(worker, 9)
        raise AssertionError("the worker process survived the timeout")


def test_tool_memory_ceiling_stops_the_whole_group(tmp_path):
    import sys

    import pytest

    from jamtriage.checks import ToolError, run_tool

    if sys.platform == "win32":
        pytest.skip("memory watchdog is macOS/Linux only")
    hog = tmp_path / "hog.py"   # a launcher whose child allocates ~300 MB, like capa's worker
    hog.write_text("import subprocess, sys\n"
                   "subprocess.run([sys.executable, '-c', 'import time; b = bytearray(300 << 20); "
                   "b[::4096] = b\"x\" * len(b[::4096]); time.sleep(60)'])\n")
    with pytest.raises(ToolError, match="more than 100 MB"):
        run_tool([sys.executable, str(hog)], timeout=30, max_mb=100)


def _verdicts(results):
    return {r["slug"]: (r["verdict"], sorted((f["rule"], f["file"]) for f in r["findings"])) for r in results}


def test_parallel_workers_give_the_same_results_as_one(cfg):
    build_fixtures(cfg.builds_dir)
    pipe = Pipeline(cfg)
    one = pipe.analyze(show_tools=False, force=True, workers=1)
    many = pipe.analyze(show_tools=False, force=True, workers=4)
    assert _verdicts(one) == _verdicts(many)
    assert [r["slug"] for r in one] == [r["slug"] for r in many]          # results keep the entry order
    run = pipe.state.get_meta("run")
    assert run["workers"] == 4 and run["analysed"] == len(many) and run["state"] == "done"
    assert pipe.state.get_meta("current")["entry"] == "" and pipe._active == {}


def test_active_entries_shown_for_every_worker(cfg):
    pipe = Pipeline(cfg)
    pipe._set_active("a", "capa")
    assert pipe.state.get_meta("current")["entry"] == "a"
    pipe._set_active("b", "strings")
    cur = pipe.state.get_meta("current")
    assert cur["entry"] == "2 entries" and cur["stage"] == "a: capa · b: strings"
    assert cur["active"] == [{"entry": "a", "stage": "capa"}, {"entry": "b", "stage": "strings"}]
    pipe._set_active("a", None)
    pipe._set_active("b", None)
    assert pipe.state.get_meta("current") == {"entry": "", "stage": "", "active": []}


def test_capa_skips_godot_engine_and_caches_output(cfg, tmp_path):
    from jamtriage.checks import EntryContext
    from jamtriage.checks import capa as capa_mod
    from jamtriage.models import FileRecord

    ctx = EntryContext(cfg=cfg, slug="g", builds_root=tmp_path, tools={})
    eng = FileRecord(path="builds/game.exe", size=100_000_000, kind="pe", sha256="a" * 64)
    ext = FileRecord(path="builds/libgame.dll", size=1000, kind="pe", sha256="b" * 64)
    ctx.files = [eng, ext]
    ctx.info = {"main_exe": eng.path, "engines": ["godot"], "unwrapped": {"godot": [eng.path]}}
    assert capa_mod.capa_candidates(ctx) == [ext]          # GDExtension DLLs are still analysed

    counter = tmp_path / "calls"
    fake = tmp_path / "capa"
    fake.write_text(f'#!/bin/sh\necho x >> "{counter}"\necho \'{{"rules": {{}}}}\'\n')
    fake.chmod(0o755)
    for _ in range(3):
        rc, out, _err = capa_mod._run_capa(ctx, str(fake), [str(fake), "-j", "x"], ext, 30)
        assert rc == 0 and json.loads(out) == {"rules": {}}
    assert counter.read_text().count("x") == 1             # later runs come from the cache
    assert list((cfg.data_dir / "cache" / "capa").glob(f"{ext.sha256}.*.json"))


def test_config_local_overrides_config(tmp_path):
    from jamtriage.config import load_config
    (tmp_path / "config.toml").write_text('[sandbox]\nconsent_all = false\n[analysis]\nworkers = 5\n')
    (tmp_path / "config.local.toml").write_text('[sandbox]\nconsent_all = true\n[tools.paths]\ncapa = "bin/capa"\n')
    c = load_config(root=tmp_path)
    assert c.section("sandbox")["consent_all"] is True and c.section("analysis")["workers"] == 5
    assert c.tool_paths()["capa"] == str(tmp_path.resolve() / "bin/capa")


def test_dashboard_lookup_column_says_off_without_services(cfg):
    from jamtriage.dashboard import entry_layers
    build_fixtures(cfg.builds_dir)
    Pipeline(cfg).analyze(show_tools=False)          # the test config enables no lookup service
    assert entry_layers(cfg, "clean-game")["lookups"]["state"] == "off"
