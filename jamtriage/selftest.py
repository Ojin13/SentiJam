"""`triage selftest`: run the full pipeline on harmless fixtures and fail loudly on any mismatch."""
from __future__ import annotations

import copy
import shutil
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .config import Config
from .entries import discover_entries
from .fixtures import EICAR_SHA256, build_fixtures
from .pipeline import Pipeline
from .state import LookupCache, State, iso_now


@dataclass
class Check:
    fixture: str
    status: str   # pass | fail | skip
    note: str = ""


def _rules(result: dict, min_sev: tuple[str, ...] = ("critical", "high", "medium", "low", "info")) -> Counter:
    return Counter(f["rule"] for f in result.get("findings", []) if f["severity"] in min_sev)


def evaluate(results: dict[str, dict], run_root: Path, av_available: bool, vt_enabled: bool,
             cache: LookupCache | None) -> list[Check]:
    out: list[Check] = []

    def need(fixture: str, cond: bool, note: str) -> None:
        out.append(Check(fixture, "pass" if cond else "fail", "" if cond else note))

    def skip(fixture: str, note: str) -> None:
        out.append(Check(fixture, "skip", note))

    r = {k: v for k, v in results.items()}
    missing = [k for k in ("eicar-plain", "eicar-zipped", "zip-slip", "encrypted-zip", "zip-bomb-lite", "fake-stealer",
                           "double-extension", "fake-electron", "fake-godot-script", "bad-web-build", "clean-game")
               if k not in r]
    for m in missing:
        out.append(Check(m, "fail", "fixture produced no result"))

    if "eicar-plain" in r:
        rules = _rules(r["eicar-plain"])
        if av_available:
            need("eicar-plain", rules["av.detection"] >= 1, "antivirus did not detect EICAR")
        else:
            skip("eicar-plain", "no antivirus engine installed (AV part)")
        if vt_enabled:
            cached = cache.get(EICAR_SHA256, "virustotal") if cache else None
            ok = rules["lookup.virustotal"] >= 1 and bool(cached) and int(cached.get("malicious", 0)) >= 3
            need("eicar-plain", ok, "VirusTotal lookup of the EICAR hash did not return detections (key, limiter, cache?)")
        else:
            skip("eicar-plain", "VirusTotal not configured (VT_API_KEY) - online part")
    if "eicar-zipped" in r:
        if av_available:
            hit = any(f["rule"] == "av.detection" and f.get("file", "").startswith("unpacked/")
                      for f in r["eicar-zipped"]["findings"])
            need("eicar-zipped", hit, "no detection on the unpacked EICAR file")
        else:
            skip("eicar-zipped", "no antivirus engine installed")
    if "zip-slip" in r:
        rules = _rules(r["zip-slip"])
        escaped = [p for p in run_root.rglob("evil.txt")]
        need("zip-slip", rules["archive.path_traversal"] >= 1 and not escaped,
             f"traversal not blocked/flagged (escaped files: {escaped})")
    if "encrypted-zip" in r:
        need("encrypted-zip", any(f["rule"] == "archive.encrypted" and f["severity"] == "high"
                                  for f in r["encrypted-zip"]["findings"]), "encrypted archive not flagged High")
    if "zip-bomb-lite" in r:
        need("zip-bomb-lite", any(f["rule"] in ("archive.limit", "archive.high_ratio")
                                  for f in r["zip-bomb-lite"]["findings"]) and r["zip-bomb-lite"].get("verdict"),
             "high-ratio archive not flagged, or the run did not continue")
    if "fake-stealer" in r:
        rules = _rules(r["fake-stealer"], ("high",))
        want = ["strings.stealer-browser-passwords", "strings.exfil-discord-webhook", "strings.api-cryptunprotectdata"]
        miss = [w for w in want if not rules[w]]
        need("fake-stealer", not miss, f"missing High string hits: {miss}")
    if "double-extension" in r:
        need("double-extension", _rules(r["double-extension"], ("high",))["file.double_extension"] >= 1,
             "cover.png.exe not flagged High")
    if "fake-electron" in r:
        res = r["fake-electron"]
        extracted = bool((res.get("info") or {}).get("unwrapped", {}).get("asar"))
        hit = any(f["rule"] == "code.javascript.child-process" and f["severity"] == "high" for f in res["findings"])
        need("fake-electron", extracted and hit, f"asar extracted={extracted}, child_process High hit={hit}")
    if "fake-godot-script" in r:
        rules = _rules(r["fake-godot-script"], ("high",))
        need("fake-godot-script", rules["code.gdscript.os-execute"] >= 1 and rules["code.gdscript.env-appdata"] >= 1,
             "GDScript OS.execute / APPDATA rules did not fire")
    if "bad-web-build" in r:
        rules = _rules(r["bad-web-build"])
        want = ["web.phishing-password", "web.external_code", "web.redirect-external", "web.crypto-miner",
                "web.download-push"]
        wrong = {w: rules[w] for w in want if rules[w] != 1}
        need("bad-web-build", not wrong and r["bad-web-build"].get("has_web"),
             f"each web rule should fire exactly once, got {wrong or 'no web build detected'}")
    if "clean-game" in r:
        res = r["clean-game"]
        noisy = [f["rule"] for f in res["findings"] if f["severity"] != "info"]
        need("clean-game", not noisy and res.get("verdict") == "Sandbox OK",
             f"over-eager rules: {noisy}, verdict {res.get('verdict')}")
    return out


def run_selftest(cfg: Config, console: Console | None = None, keep: bool = False, offline: bool = False) -> bool:
    console = console or Console()
    run_root = cfg.data_dir / "selftest"
    shutil.rmtree(run_root, ignore_errors=True)
    raw = copy.deepcopy(cfg.raw)
    raw["paths"] = {"data": str(run_root / "data"), "out": str(run_root / "out"), "rules": str(cfg.rules_dir)}
    raw["malwarebazaar"] = {**raw.get("malwarebazaar", {}), "enabled": False}
    raw["metadefender"] = {**raw.get("metadefender", {}), "enabled": False}
    if offline:
        raw["virustotal"] = {**raw.get("virustotal", {}), "enabled": False}
    tcfg = Config(root=cfg.root, raw=raw, platform=cfg.platform, selftest=True, lookup_allowlist={EICAR_SHA256})
    tcfg.ensure_dirs()
    build_fixtures(tcfg.builds_dir)
    console.print(f"[bold]Self-test[/] on {cfg.platform}: fixtures in {tcfg.builds_dir}")

    pipe = Pipeline(tcfg, console)
    vt_enabled = "virustotal" in pipe.services
    av_key = "defender" if cfg.platform == "windows" else "clamav"
    av_available = pipe.tools.get(av_key) is not None and pipe.tools[av_key].status == "available"
    results_list = pipe.analyze(discover_entries(tcfg.builds_dir), force=True)
    results = {r["slug"]: r for r in results_list}
    checks = evaluate(results, run_root, av_available, vt_enabled, LookupCache(tcfg.cache_file))

    # The self-test's VirusTotal lookups count against the real daily budget too.
    main_state = State(cfg.state_db)
    used = State(tcfg.state_db).quota_used("virustotal")
    if used:
        main_state.quota_add("virustotal", used)

    table = Table(title="Self-test results")
    table.add_column("Fixture")
    table.add_column("Result")
    table.add_column("Note")
    colors = {"pass": "green", "fail": "bold red", "skip": "yellow"}
    for c in checks:
        table.add_row(c.fixture, f"[{colors[c.status]}]{c.status.upper()}[/]", c.note)
    console.print(table)
    passed = not any(c.status == "fail" for c in checks)
    skipped = [c for c in checks if c.status == "skip"]
    main_state.set_meta("selftest", {"passed": passed, "when": iso_now(), "platform": cfg.platform,
                                     "results": [c.__dict__ for c in checks]})
    if passed:
        console.print("[bold green]SELF-TEST PASSED[/]" + (f" [yellow]({len(skipped)} part(s) skipped: install the "
                                                             f"missing tools/keys to cover them)[/]" if skipped else ""))
    else:
        console.print("[bold red]SELF-TEST FAILED[/] - do not trust a real run until this is fixed.")
    if not keep:
        shutil.rmtree(run_root / "data" / "unpacked", ignore_errors=True)
        shutil.rmtree(run_root / "data" / "unwrapped", ignore_errors=True)
    return passed
