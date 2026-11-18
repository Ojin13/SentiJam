"""Batch VirusTotal sandboxing: consent, budget, resumability, merging results."""
from __future__ import annotations

import struct
import time

import pytest
from rich.console import Console

from jamtriage.sandbox import virustotal as vtsandbox
from jamtriage.fixtures import tiny_pe
from jamtriage.pipeline import Pipeline
from jamtriage.state import LookupCache, State


class FakeVT:
    uploads: list = []
    reports: dict = {}
    behaviours: dict = {}

    def __init__(self, key):
        pass

    def upload(self, path, size):
        FakeVT.uploads.append(path.name)
        return f"analysis-{len(FakeVT.uploads)}"

    def lookup(self, sha):
        return FakeVT.reports.get(sha, {"found": True, "malicious": 0, "total": 70, "detections": []})

    def behaviour_summary(self, sha):
        return FakeVT.behaviours.get(sha)


@pytest.fixture
def setup(cfg, monkeypatch):
    FakeVT.uploads, FakeVT.reports, FakeVT.behaviours = [], {}, {}
    monkeypatch.setattr(vtsandbox, "VirusTotal", FakeVT)
    monkeypatch.setenv("VT_API_KEY", "test")
    cfg.raw["virustotal"].update({"premium": True, "requests_per_minute": 600000, "daily_budget": 1000})
    cfg.raw["sandbox"].update({"consent_all": True, "min_age_minutes": 0})
    for slug in ("alpha", "beta", "gamma"):
        d = cfg.builds_dir / slug
        d.mkdir(parents=True)
        (d / "Game.exe").write_bytes(tiny_pe(slug.encode() * 50))
    web = cfg.builds_dir / "webonly"
    web.mkdir()
    (web / "index.html").write_text("<html><body>hi</body></html>")
    Pipeline(cfg).analyze(show_tools=False)
    return cfg


def _sha(cfg, slug):
    import json
    from jamtriage.pipeline import local_path
    local = json.loads(local_path(cfg, slug).read_text())
    return next(f["sha256"] for f in local["files"] if f["path"] == local["info"]["main_exe"])


def test_upload_skips_known_files_web_only_and_non_consenting(setup):
    cfg = setup
    LookupCache(cfg.cache_file).put(_sha(cfg, "beta"), "virustotal", {"found": True, "malicious": 0, "total": 70})
    con = Console(quiet=True)
    rows = {r["slug"]: r["action"] for r in vtsandbox.plan(cfg, con)}
    assert rows["alpha"] == "upload" and rows["beta"].startswith("known") and rows["webonly"].startswith("skip")
    vtsandbox.upload_all(cfg, con)
    assert sorted(FakeVT.uploads) == ["Game.exe", "Game.exe"]          # alpha + gamma, not beta (known)
    st = State(cfg.state_db)
    assert st.sandbox_get("beta")["status"] == "known" and st.sandbox_get("webonly")["status"] == "skipped"
    vtsandbox.upload_all(cfg, con)                                      # resumable: nothing uploaded twice
    assert len(FakeVT.uploads) == 2


def test_consent_is_required(setup):
    cfg = setup
    cfg.raw["sandbox"]["consent_all"] = False
    vtsandbox.upload_all(cfg, Console(quiet=True))
    assert FakeVT.uploads == []
    assert State(cfg.state_db).sandbox_get("alpha")["note"] == "no consent"


def test_collect_merges_behaviour_and_waits_for_missing_reports(setup):
    cfg = setup
    con = Console(quiet=True)
    vtsandbox.upload_all(cfg, con)
    a = _sha(cfg, "alpha")
    FakeVT.behaviours[a] = {"files_opened": ["C:\\Users\\x\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"],
                            "registry_keys_set": [{"key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\u"}]}
    FakeVT.reports[a] = {"found": True, "malicious": 0, "total": 70, "detections": [],
                         "sandbox_verdicts": [{"sandbox": "Zenbox", "category": "malicious", "names": ["Lumma"]}]}
    vtsandbox.collect_all(cfg, con)
    st = State(cfg.state_db)
    assert st.sandbox_get("alpha")["status"] == "collected"
    import json
    res = json.loads((cfg.results_dir / "alpha.json").read_text())
    rules = {f["rule"] for f in res["findings"]}
    assert {"detonation.browser_data", "detonation.autostart", "detonation.vt_sandbox_malicious"} <= rules
    assert res["verdict"] == "Disqualify"
    assert st.sandbox_get("gamma")["status"] == "waiting"           # no report yet: try again later
    st.sandbox_set("gamma", checked=time.time() - 3 * 3600, attempts=vtsandbox.MAX_COLLECT_ATTEMPTS - 1)
    vtsandbox.collect_all(cfg, con)
    assert st.sandbox_get("gamma")["status"] == "no_report"
    res = json.loads((cfg.results_dir / "gamma.json").read_text())
    assert res["verdict"] == "Sandbox OK"                            # quiet run never changes the verdict


def test_batch_stops_cleanly_at_the_budget(setup):
    cfg = setup
    cfg.raw["virustotal"]["daily_budget"] = 1
    con = Console(quiet=True)
    vtsandbox.upload_all(cfg, con)
    assert len(FakeVT.uploads) == 1                                  # 1 request allowed, then a clean stop
    cfg.raw["virustotal"]["daily_budget"] = 1000
    vtsandbox.upload_all(cfg, con)                                   # next run picks up the rest
    assert len(FakeVT.uploads) == 3


def test_sandboxing_is_off_by_default(cfg, monkeypatch):
    """Only static analysis by default: no config switch can turn uploads on, only a command flag."""
    from jamtriage.config import DEFAULTS
    assert "enabled" not in DEFAULTS["sandbox"]
    FakeVT.uploads = []
    monkeypatch.setattr(vtsandbox, "VirusTotal", FakeVT)
    monkeypatch.setenv("VT_API_KEY", "test")
    cfg.raw["sandbox"]["consent_all"] = True
    d = cfg.builds_dir / "g"
    d.mkdir(parents=True)
    (d / "Game.exe").write_bytes(tiny_pe(b"x"))
    pipe = Pipeline(cfg)
    pipe.services = ["virustotal"]
    pipe.lookup_clients = {"virustotal": type("U", (), {"lookup": lambda self, sha: {"found": False}})()}
    pipe.analyze(show_tools=False)
    assert FakeVT.uploads == []


def test_analyze_runs_the_sandbox_step_only_with_the_flag(setup, monkeypatch):
    cfg = setup
    pipe = Pipeline(cfg)
    pipe.services = ["virustotal"]
    class Unknown:
        def lookup(self, sha):
            return {"found": False}
    pipe.lookup_clients = {"virustotal": Unknown()}
    pipe.analyze(show_tools=False, force=True)
    assert FakeVT.uploads == []
    pipe.analyze(show_tools=False, sandbox=True)
    assert len(FakeVT.uploads) == 3                                  # alpha, beta, gamma (not the web-only one)


def test_changed_build_is_uploaded_again_and_old_results_dropped(setup):
    cfg = setup
    con = Console(quiet=True)
    vtsandbox.upload_all(cfg, con)
    a = _sha(cfg, "alpha")
    FakeVT.reports[a] = {"found": True, "malicious": 0, "total": 70, "detections": [],
                         "sandbox_verdicts": [{"sandbox": "Zenbox", "category": "malicious", "names": ["Lumma"]}]}
    vtsandbox.collect_all(cfg, con)
    (cfg.builds_dir / "alpha" / "Game.exe").write_bytes(tiny_pe(b"a fixed, different build" * 40))
    Pipeline(cfg).analyze(show_tools=False)
    import json
    res = json.loads((cfg.results_dir / "alpha.json").read_text())
    assert not any(f["rule"].startswith("detonation.") for f in res["findings"])   # old exe's results gone
    vtsandbox.upload_all(cfg, con)
    assert len(FakeVT.uploads) == 4                                  # the new exe was uploaded


# ----------------------------------------------------------------------------- Hybrid Analysis batch

class FakeHASession:
    """Stands in for requests.Session inside the real HybridClient, so limiter integration is real."""
    def __init__(self):
        self.calls, self.jobs, self.states, self.summaries = [], 0, {}, {}
        self.level = "default"

    def request(self, method, url, **kw):
        self.calls.append((method, url.rsplit("/api/v2", 1)[-1]))
        if url.endswith("/key/current"):
            return _Resp(200, {"auth_level": 1, "auth_level_name": self.level})
        if url.endswith("/submit/file"):
            if self.level == "restricted":
                return _Resp(404, {"message": "Requested URI - Not Found"})
            self.jobs += 1
            return _Resp(200, {"job_id": f"job{self.jobs}"})
        job = url.split("/report/")[1].split("/")[0]
        if url.endswith("/state"):
            return _Resp(200, {"state": self.states.get(job, "IN_QUEUE")})
        return _Resp(200, self.summaries.get(job, {}))


class _Resp:
    def __init__(self, code, data):
        self.status_code, self._data, self.text, self.headers = code, data, json.dumps(data), {}

    def json(self):
        return self._data


import json  # noqa: E402


@pytest.fixture
def ha(setup, monkeypatch):
    from jamtriage.sandbox import detonate
    session = FakeHASession()
    real = detonate.HybridClient

    class Client(real):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.s = session

    monkeypatch.setattr(detonate, "HybridClient", Client)
    monkeypatch.setenv("HA_API_KEY", "test")
    setup.raw["hybridanalysis"].update({"requests_per_minute": 6000, "submissions_per_minute": 6000})
    return setup, session


def test_analyze_sandbox_runs_both_sandboxes(ha):
    cfg, session = ha
    pipe = Pipeline(cfg)
    pipe.services = ["virustotal"]
    pipe.lookup_clients = {"virustotal": type("U", (), {"lookup": lambda self, sha: {"found": False}})()}
    pipe.analyze(show_tools=False)
    assert FakeVT.uploads == [] and session.jobs == 0             # no flag: static only
    pipe.analyze(show_tools=False, sandbox=True)
    assert len(FakeVT.uploads) == 3 and session.jobs == 3          # both sandboxes, 3 entries with an exe
    st = State(cfg.state_db)
    assert State(cfg.state_db).quota_used("hybrid-submit") == 3
    assert st.quota_used("hybrid") == len(session.calls)          # every HTTP call went through the limiter


def test_hybrid_daily_submission_limit_and_resume(ha):
    from jamtriage.sandbox import hybrid as hasandbox
    cfg, session = ha
    cfg.raw["hybridanalysis"]["daily_submissions"] = 2
    hasandbox.upload_all(cfg, Console(quiet=True))
    assert session.jobs == 2                                        # stopped cleanly at the daily limit
    cfg.raw["hybridanalysis"]["daily_submissions"] = 95            # "next day"
    hasandbox.upload_all(cfg, Console(quiet=True))
    assert session.jobs == 3                                        # only the remaining entry


def test_hybrid_free_tier_is_clamped(cfg):
    from jamtriage.lookups import hybrid_limiters
    cfg.raw["hybridanalysis"].update({"daily_submissions": 500, "requests_per_minute": 1000})
    req, sub = hybrid_limiters(cfg, State(cfg.state_db))
    assert sub.budget == 100 and abs(60 / req.interval - 200) < 1e-6
    cfg.raw["hybridanalysis"]["premium"] = True
    assert hybrid_limiters(cfg, State(cfg.state_db))[1].budget == 500


def test_hybrid_collect_maps_report_and_ignores_informational_signatures(ha):
    from jamtriage.sandbox import hybrid as hasandbox
    cfg, session = ha
    con = Console(quiet=True)
    hasandbox.upload_all(cfg, con)
    st = State(cfg.state_db)
    jobs = {r["slug"]: r["ref"] for r in st.sandbox_all("hybrid")}
    session.states = {jobs["alpha"]: "SUCCESS", jobs["beta"]: "SUCCESS"}
    session.summaries = {
        jobs["alpha"]: {"verdict": "malicious", "threat_score": 95, "vx_family": "Lumma",
                        "signatures": [{"name": "Reads browser data", "threat_level": 2,
                                        "description": "Reads Login Data of Chrome"}]},
        jobs["beta"]: {"verdict": "no specific threat", "threat_score": 5,
                       "signatures": [{"name": "Spawns processes", "threat_level": 0,
                                       "description": "runs cmd.exe and checks for a virtual machine"}]},
    }
    hasandbox.collect_all(cfg, con)
    res_a = json.loads((cfg.results_dir / "alpha.json").read_text())
    res_b = json.loads((cfg.results_dir / "beta.json").read_text())
    assert res_a["verdict"] == "Disqualify"
    assert {"detonation.family", "detonation.browser_data"} <= {f["rule"] for f in res_a["findings"]}
    assert res_b["verdict"] == "Sandbox OK"                          # informational signatures ignored
    assert st.sandbox_get("gamma", "hybrid")["status"] == "waiting"  # still queued: collected later


def test_hybrid_restricted_key_is_explained_not_404(ha):
    from jamtriage.sandbox import hybrid as hasandbox
    cfg, session = ha
    session.level = "restricted"
    con = Console(record=True, width=200)
    assert hasandbox.upload_all(cfg, con) == 3
    out = con.export_text()
    assert session.jobs == 0 and "restricted" in out and "Upgrade API key" in out
    assert State(cfg.state_db).quota_used("hybrid-submit") == 0     # no submission slot wasted


def test_sandbox_verdict_filter_picks_only_flagged_entries(cfg):
    import json as _json

    from jamtriage.cli import main
    cfg.results_dir.mkdir(parents=True, exist_ok=True)
    for slug, verdict in [("a", "Review"), ("b", "Sandbox OK"), ("c", "Review"), ("d", "Web")]:
        (cfg.results_dir / f"{slug}.json").write_text(_json.dumps({"slug": slug, "verdict": verdict}))
    assert vtsandbox.slugs_with_verdict(cfg, ["review"]) == ["a", "c"]
    assert vtsandbox.slugs_with_verdict(cfg, ["review", "web"]) == ["a", "c", "d"]
    assert vtsandbox.slugs_with_verdict(cfg, ["disqualify"]) == []


def test_sandbox_verdict_filter_with_no_match_does_nothing(tmp_path, monkeypatch, capsys):
    import json as _json

    from jamtriage import cli
    (tmp_path / "config.toml").write_text('[paths]\ndata = "data"\nout = "out"\n')
    res = tmp_path / "data" / "results"
    res.mkdir(parents=True)
    (res / "a.json").write_text(_json.dumps({"slug": "a", "verdict": "Sandbox OK"}))
    called = []
    monkeypatch.setattr(vtsandbox, "run", lambda *a, **k: called.append(a) or 0)
    monkeypatch.setattr(vtsandbox, "available", lambda cfg: ["virustotal"])
    rc = cli.main(["--config", str(tmp_path / "config.toml"), "sandbox", "upload", "--verdict", "review"])
    assert rc == 0 and called == []          # never falls back to "every entry"


def test_sandbox_uploads_the_whole_archive_for_an_extracted_game(cfg):
    """A Unity exe is only a launcher; on its own it can't start, so the original zip goes to the sandbox."""
    root = cfg.builds_dir / "unity"
    (root / "files").mkdir(parents=True)
    (root / "files" / "Game.zip").write_bytes(b"PK" + b"0" * 100)
    exe_dir = cfg.unpacked_dir / "unity" / "Game.zip" / "Game"
    exe_dir.mkdir(parents=True)
    (exe_dir / "Game.exe").write_bytes(tiny_pe(b"stub"))
    local = {"slug": "unity", "entry": {"root": str(root)},
             "info": {"main_exe": "unpacked/Game.zip/Game/Game.exe"},
             "files": [{"path": "builds/files/Game.zip", "sha256": "a" * 64, "size": 102, "kind": "archive"},
                       {"path": "unpacked/Game.zip/Game/Game.exe", "sha256": "b" * 64, "size": 10}]}
    rel, path, sha, why = vtsandbox._target(cfg, local)
    assert (rel, sha, why) == ("builds/files/Game.zip", "a" * 64, "")
    assert path.is_file()
    # archive over the provider's limit: fall back to the exe
    rel, _path, sha, why = vtsandbox._target(cfg, local, max_bytes=50)
    assert (rel, sha, why) == ("unpacked/Game.zip/Game/Game.exe", "b" * 64, "")
    # a loose exe (not from an archive) is still uploaded as itself
    assert vtsandbox._source_archive(local, "builds/files/Game.exe") is None


def test_sandbox_uses_the_unreal_game_exe_not_its_launcher_when_the_archive_is_too_big(cfg):
    root = cfg.builds_dir / "ue"
    (root / "files").mkdir(parents=True)
    (root / "files" / "Big.zip").write_bytes(b"PK" + b"0" * 100)
    base = cfg.unpacked_dir / "ue" / "Big.zip" / "Win"
    (base / "Game" / "Binaries" / "Win64").mkdir(parents=True)
    (base / "Game.exe").write_bytes(tiny_pe(b"launcher"))
    (base / "Game" / "Binaries" / "Win64" / "Game-Win64-Shipping.exe").write_bytes(tiny_pe(b"game"))
    ship = "unpacked/Big.zip/Win/Game/Binaries/Win64/Game-Win64-Shipping.exe"
    local = {"slug": "ue", "entry": {"root": str(root)}, "info": {"main_exe": "unpacked/Big.zip/Win/Game.exe"},
             "files": [{"path": "builds/files/Big.zip", "sha256": "a" * 64, "size": 102, "kind": "archive"},
                       {"path": "unpacked/Big.zip/Win/Game.exe", "sha256": "b" * 64, "size": 10, "kind": "pe"},
                       {"path": ship, "sha256": "c" * 64, "size": 10, "kind": "pe"}]}
    assert vtsandbox._target(cfg, local)[0] == "builds/files/Big.zip"                 # archive fits: whole game
    rel, _p, sha, why = vtsandbox._target(cfg, local, max_bytes=50)                 # too big: the real game exe
    assert (rel, sha, why) == (ship, "c" * 64, "")



def test_sandbox_uploads_a_self_contained_godot_exe_on_its_own(cfg):
    """A Godot exe with its game pack embedded runs alone, so it goes up instead of the whole archive."""
    root = cfg.builds_dir / "gd"
    (root / "files").mkdir(parents=True)
    (root / "files" / "Game.zip").write_bytes(b"PK" + b"0" * 100)
    exe_dir = cfg.unpacked_dir / "gd" / "Game.zip"
    exe_dir.mkdir(parents=True)
    pack = b"GDPC" + b"\0" * 60
    (exe_dir / "game.exe").write_bytes(tiny_pe(b"godot") + pack + struct.pack("<Q", len(pack)) + b"GDPC")
    (exe_dir / "bare.exe").write_bytes(tiny_pe(b"godot GDPC"))     # engine only, game in a .pck beside it
    files = [{"path": "builds/files/Game.zip", "sha256": "a" * 64, "size": 102, "kind": "archive"},
             {"path": "unpacked/Game.zip/game.exe", "sha256": "b" * 64, "size": 10, "kind": "pe"},
             {"path": "unpacked/Game.zip/bare.exe", "sha256": "c" * 64, "size": 10, "kind": "pe",
              "tags": ["godot-embedded"]}]                                  # stale tag from an old run
    local = {"slug": "gd", "entry": {"root": str(root)}, "info": {"main_exe": "unpacked/Game.zip/game.exe"},
             "files": files}
    rel, path, sha, why = vtsandbox._target(cfg, local)
    assert (rel, sha, why) == ("unpacked/Game.zip/game.exe", "b" * 64, "")
    assert path.is_file()
    local["info"]["main_exe"] = "unpacked/Game.zip/bare.exe"                # bare engine: the zip, not the tag
    assert vtsandbox._target(cfg, local)[0] == "builds/files/Game.zip"

# --- VirusTotal behaviour mapping: sandbox noise vs real behaviour --------------------------------------

def _texts_and_findings(summary, own=frozenset()):
    from jamtriage.sandbox.detonate import _vt_behaviour_texts, map_behaviour
    return {f.rule for f in map_behaviour(_vt_behaviour_texts(summary, own), None, [], "virustotal-sandbox")
            if f.rule != "detonation.quiet"}            # collect drops the "quiet run" note too


def test_sandbox_noise_every_game_produces_is_not_a_finding():
    summary = {
        # VirusTotal test-loading the uploaded zip's own DLLs, and its unpacker
        "command_executions": [r'"C:\Windows\system32\rundll32.exe" "C:\Users\u\AppData\Local\Temp\x\Game_Data\Managed\System.Runtime.dll",#1',
                               r'C:\Windows\SysWOW64\7za.exe x -pinfected -y -o"C:\Users\u\AppData\Local\Temp\x" Game.zip'],
        # unpacking the zip writes the game's own exe, which then starts
        "files_written": [r"C:\Users\u\AppData\Local\Temp\x\Game.exe"],
        "processes_created": [r'"C:\Users\u\AppData\Local\Temp\x\Game.exe"'],
        "signature_matches": [
            {"name": "antivm_display", "severity": "IMPACT_SEVERITY_MEDIUM",
             "description": "Attempts to query display device information, possibly to determine if virtualized"},
            {"name": "injection_rwx", "severity": "IMPACT_SEVERITY_LOW", "description": "Creates RWX memory"},
            {"id": "116", "severity": "IMPACT_SEVERITY_INFO", "description": "Found dropped PE file which has not been started"}],
        "mitre_attack_techniques": [{"id": "T1082", "severity": "IMPACT_SEVERITY_INFO",
                                     "signature_description": "Checks available memory"}],
    }
    assert _texts_and_findings(summary, {"system.runtime.dll", "game.exe", "game.zip"}) == set()


def test_real_malicious_behaviour_is_still_caught():
    summary = {
        "command_executions": [r'powershell -w hidden -enc AAAA',
                               r'"C:\Windows\system32\rundll32.exe" "C:\Users\u\AppData\Roaming\evil.dll",#1'],
        "files_written": [r"C:\Users\u\AppData\Roaming\upd\svc.exe"],
        "processes_created": [r'"C:\Users\u\AppData\Roaming\upd\svc.exe" --hidden'],
        "files_opened": [r"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Login Data"],
        "http_conversations": [{"url": "https://discord.com/api/webhooks/1/abc"}],
        "signature_matches": [{"name": "antivm_vbox_keys", "severity": "IMPACT_SEVERITY_HIGH",
                               "description": "Detects VirtualBox through the presence of registry keys"}],
    }
    got = _texts_and_findings(summary, {"game.exe"})
    assert {"detonation.shell", "detonation.dropper", "detonation.browser_data", "detonation.exfil",
            "detonation.anti_vm"} <= got


def test_one_sandbox_malware_label_is_high_and_corroborated_is_critical():
    from jamtriage.models import Severity
    one = {"malicious": 1, "sandbox_verdicts": [{"category": "malicious", "sandbox": "CAPE", "names": ["X"]}]}
    assert [f.severity for f in vtsandbox._verdict_findings(one)] == [Severity.HIGH]
    two_boxes = {"malicious": 0, "sandbox_verdicts": [{"category": "malicious", "sandbox": "CAPE", "names": ["X"]},
                                                      {"category": "malicious", "sandbox": "Zenbox", "names": []}]}
    assert {f.severity for f in vtsandbox._verdict_findings(two_boxes)} == {Severity.CRITICAL}
    av_agrees = {"malicious": 5, "sandbox_verdicts": [{"category": "malicious", "sandbox": "CAPE", "names": ["X"]}]}
    assert [f.severity for f in vtsandbox._verdict_findings(av_agrees)] == [Severity.CRITICAL]


def test_memory_yara_engine_noise_ignored_but_other_rules_kept():
    def sig(*rules):
        return {"signature_matches": [{"name": "procmem_yara", "severity": "IMPACT_SEVERITY_MEDIUM",
                                       "description": "Yara detections observed in process dumps, payloads or dropped files",
                                       "match_data": [f"Yara rule '{r}' with data '['{{ CA FE BA BE }}']'" for r in rules]}]}
    assert _texts_and_findings(sig("embedded_macho", "vmdetect")) == set()
    assert _texts_and_findings(sig("embedded_macho", "Stealer_payload")) == {"detonation.memory_yara"}


def test_same_finding_in_two_copies_of_a_godot_pack_counts_once():
    from jamtriage.models import Finding, Severity
    from jamtriage.scoring import verdict
    f = lambda path, rule="code.gdscript.shell-open-computed": Finding(rule=rule, severity=Severity.MEDIUM, title="t", file=path)
    two_copies = [f("unwrapped/godot/01/scripts/credits.gd"), f("unwrapped/godot/02/scripts/credits.gd"),
                  f("builds/files/game.exe", "lookup.virustotal_weak")]
    assert verdict(two_copies, has_web=False)[0] == "Sandbox OK"
    three_issues = two_copies + [f("unwrapped/godot/01/scripts/other.gd")]
    assert verdict(three_issues, has_web=False)[0] == "Review"
