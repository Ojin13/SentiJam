"""Progress dashboard: FastAPI on 127.0.0.1 serving GET /api/status and web/index.html."""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime
from pathlib import Path

from .config import Config
from .models import Severity
from .scoring import independent_sources
from .pipeline import RUN_STEPS, quota_status, result_path
from .state import State

WEB_DIR = Path(__file__).resolve().parent / "web"
SEV_ORDER = ["critical", "high", "medium", "low", "info"]

# Which layer of the unified view a finding belongs to, by its `source`.
LOOKUP_SOURCES = {"virustotal", "malwarebazaar", "metadefender", "lookups"}
SANDBOX_SOURCES = {"virustotal": {"virustotal-sandbox", "virustotal-behaviour"},
                   "hybrid": {"hybrid-sandbox", "hybrid-analysis"}}
SANDBOX_KEYS = {"virustotal": "VT_API_KEY", "hybrid": "HA_API_KEY"}
SANDBOX_NAMES = {"virustotal": "VirusTotal", "hybrid": "Hybrid Analysis"}
# sandbox_runs.status -> progress bucket
SANDBOX_BUCKET = {"uploaded": "running", "known": "running", "submitted": "running", "waiting": "running",
                  "collected": "collected", "no_report": "no_report", "skipped": "skipped", "error": "error"}
LAYERS = ("static", "lookups", "virustotal", "hybrid")

_layer_cache: dict[str, tuple[float, dict]] = {}


def _layer(source: str) -> str:
    if source in LOOKUP_SOURCES:
        return "lookups"
    for prov, sources in SANDBOX_SOURCES.items():
        if source in sources:
            return prov
    return "static"


def entry_layers(cfg: Config, slug: str) -> dict:
    """Worst severity and flag count (Medium or worse) per layer for one entry, from its result file.
    Cached by file mtime so the 2-second poll doesn't re-read 150 JSON files."""
    p = result_path(cfg, slug)
    try:
        mtime = p.stat().st_mtime
    except OSError:
        return {}
    hit = _layer_cache.get(slug)
    if hit and hit[0] == mtime:
        return hit[1]
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    worst = {k: Severity.INFO for k in LAYERS}
    seen = dict.fromkeys(LAYERS, False)
    flags = dict.fromkeys(LAYERS, 0)
    for f in data.get("findings") or []:
        try:
            sev = Severity.parse(f.get("severity", "info"))
        except (KeyError, ValueError):
            continue
        k = _layer(str(f.get("source", "")))
        seen[k] = True
        worst[k] = max(worst[k], sev)
        flags[k] += sev >= Severity.MEDIUM
    hybrid = ((data.get("info") or {}).get("sandbox") or {}).get("hybrid") or {}
    out = {k: {"worst": worst[k].label if seen[k] and worst[k] >= Severity.LOW else "", "flags": flags[k]}
           for k in LAYERS}
    # "off" = no lookup service was enabled; "none" = enabled, but no file was worth looking up (e.g. web only).
    looked_up = any((data.get("lookups") or {}).values())
    out["lookups"]["state"] = ("off" if not data.get("lookup_services") else "" if looked_up or seen["lookups"]
                               else "none")
    out["threat_score"] = hybrid.get("threat_score")
    out["sources"] = data["sources"] if "sources" in data else independent_sources(data.get("findings") or [])
    _layer_cache[slug] = (mtime, out)
    return out


LOOKUP_NAMES = {"virustotal": "VirusTotal", "malwarebazaar": "MalwareBazaar", "metadefender": "MetaDefender"}


def lookup_progress(quota: dict) -> tuple[str, int | None]:
    """("VirusTotal 8 left (~2m) · MalwareBazaar done", seconds until the last lookup) from quota_status."""
    parts, eta = [], 0
    for svc, name in LOOKUP_NAMES.items():
        q = quota.get(svc) or {}
        if not q.get("enabled"):
            continue
        n = int(q.get("pending") or 0)
        if not n:
            parts.append(f"{name} done")
            continue
        if q.get("budget") and q.get("used_today", 0) >= q["budget"]:
            parts.append(f"{name} {n} left: daily budget used up, continues on the next run")
            continue
        secs = int(n / max(float(q.get("requests_per_minute") or 1), 0.01) * 60) + int(q.get("next_request_in") or 0)
        eta = max(eta, secs)
        mins = max(1, round(secs / 60))
        parts.append(f"{name} {n} left (~{mins} min at {q.get('requests_per_minute'):g}/min)")
    return " · ".join(parts), (eta or None)


def run_steps(run: dict, current: dict, done: int, total: int) -> list[dict]:
    """The run's steps with live detail. Runs started before steps were recorded get them inferred."""
    steps = [dict(st) for st in run.get("steps") or []]
    if not steps and run:
        stage = (current or {}).get("stage", "")
        finished = run.get("state") == "done"
        static_done = finished or (total and done >= total)
        order = ["static", "clamav", "lookups", "score", "sandbox"]
        at = ("clamav" if stage == "ClamAV batch scan" else "lookups" if stage == "hash lookups"
              else "sandbox" if "sandbox" in stage.lower() else "static" if not static_done else "score")
        for key, title in RUN_STEPS:
            if finished:
                state = "done"
            else:
                state = ("done" if order.index(key) < order.index(at) else "running" if key == at else "pending")
            detail = ""
            if key == "sandbox" and state != "running":     # can't tell whether this older run used --sandbox
                state, detail = "skipped", "not recorded for this run (started before step tracking)"
            steps.append({"key": key, "title": title, "state": state, "detail": detail})
    return steps


def sandbox_status(cfg: Config, state: State, entries: list[dict], layers: dict[str, dict]) -> dict:
    """Per-provider progress over the shown entries, plus each entry's sandbox state."""
    out = {}
    for prov in SANDBOX_SOURCES:
        rows = {r["slug"]: r for r in state.sandbox_all(prov)}
        counts = dict.fromkeys(("not_started", "running", "collected", "no_report", "skipped", "error"), 0)
        per_entry = {}
        for e in entries:
            r = rows.get(e["slug"])
            bucket = SANDBOX_BUCKET.get(r["status"], "not_started") if r else "not_started"
            counts[bucket] += 1
            per_entry[e["slug"]] = {"status": bucket, "detail": (r or {}).get("note") or "",
                                    "attempts": (r or {}).get("attempts", 0)}
        flagged = sum(1 for e in entries if layers.get(e["slug"], {}).get(prov, {}).get("flags"))
        out[prov] = {"name": SANDBOX_NAMES[prov], "enabled": bool(cfg.key(SANDBOX_KEYS[prov])),
                     "total": len(entries), **counts, "flagged": flagged, "entries": per_entry}
    return out


def build_status(cfg: Config, state: State) -> dict:
    run = state.get_meta("run", {}) or {}
    entries = state.entries()
    live = run.get("state") == "running"
    if live and run.get("slugs") is not None:   # during a run: only this run's entries
        wanted = set(run["slugs"])
        entries = [e for e in entries if e["slug"] in wanted]
    elif not live:                               # afterwards: every entry that has a result on disk
        have = {p.stem for p in cfg.results_dir.glob("*.json")}
        entries = [e for e in entries if e["slug"] in have]
    total = (run.get("total") if live else None) or len(entries)
    by_status = {"done": 0, "in_progress": 0, "queued": 0, "errors": 0, "provisional": 0}
    verdicts = {"web": 0, "sandbox_ok": 0, "review": 0, "disqualify": 0}
    findings = {s: 0 for s in SEV_ORDER[:-1]}
    flagged = []
    for e in entries:
        st = e.get("status") or "queued"
        st = "in_progress" if st == "reused" else st
        if st == "provisional":
            by_status["done"] += 1          # local checks finished; lookups / AV batch still pending
        by_status[st if st in by_status else "queued"] += 1
        if e.get("counts", {}).get("errors"):
            by_status["errors"] += 1
        v = (e.get("verdict") or "").lower().replace(" ", "_")
        if v in verdicts and st in ("done", "provisional"):
            verdicts[v] += 1
        for s in findings:
            findings[s] += int(e.get("counts", {}).get(s, 0))
        if e.get("verdict") in ("Review", "Disqualify"):
            flagged.append({"entry": e["slug"], "severity": e.get("top_severity", ""),
                            "finding": e.get("top_finding", ""), "verdict": e["verdict"]})
    flagged.sort(key=lambda f: (SEV_ORDER.index(f["severity"]) if f["severity"] in SEV_ORDER else 9, f["entry"]))
    started_ts = run.get("started_ts")
    eta = None
    analysed, reused = int(run.get("analysed", 0)), int(run.get("reused", 0))
    if started_ts and analysed and run.get("state") == "running" and total:
        # Reused (unchanged) entries take no time: base the estimate on entries actually analysed.
        remaining = max(0, total - analysed - reused)
        eta = int((time.time() - started_ts) / analysed * remaining)
    current = state.get_meta("current", {}) or {}
    quota = quota_status(cfg, state)
    steps = run_steps(run, current, by_status["done"], total)
    lookup_detail, lookup_eta = lookup_progress(quota)
    for st in steps:
        if st["state"] != "running":
            continue
        if st["key"] == "static":
            w = int(run.get("workers") or 1)
            st["detail"] = f"{by_status['done']}/{total} entries" + (f" · {w} workers" if w > 1 else "") + (
                f" · now {current['entry']} :: {current['stage']}" if current.get("entry") else "")
        elif st["key"] == "lookups":
            st["detail"] = lookup_detail
            if live and lookup_eta and by_status["done"] >= total:
                eta = lookup_eta
        elif st["key"] == "clamav":
            st["detail"] = "one pass over every entry; can take several minutes"
    layers = {e["slug"]: entry_layers(cfg, e["slug"]) for e in entries}
    sandbox = sandbox_status(cfg, state, entries, layers)
    rank = {"Disqualify": 0, "Review": 1, "Web": 2, "Sandbox OK": 3}
    table = []
    for e in entries:
        lay = layers.get(e["slug"], {})
        table.append({
            "entry": e["slug"], "status": e.get("status") or "queued", "verdict": e.get("verdict") or "",
            "sources": lay.get("sources", []),
            "static": lay.get("static", {}), "lookups": lay.get("lookups", {}),
            "virustotal": {**sandbox["virustotal"]["entries"][e["slug"]], **lay.get("virustotal", {})},
            "hybrid": {**sandbox["hybrid"]["entries"][e["slug"]], **lay.get("hybrid", {}),
                       "threat_score": lay.get("threat_score")},
        })
    table.sort(key=lambda r: (rank.get(r["verdict"], 4), -len(r["sources"]), r["entry"]))
    for prov in sandbox.values():
        del prov["entries"]
    log = [f"{datetime.fromtimestamp(r['ts']).strftime('%H:%M:%S')} {r['entry'] or '-':<14} {r['message']}"
           for r in state.recent_log(20)]
    return {
        "state": run.get("state", "idle"),
        "started": run.get("started"),
        "elapsed_seconds": int(time.time() - started_ts) if started_ts and run.get("state") == "running" else None,
        "eta_seconds": eta,
        "entries": {"total": total, **by_status},
        "verdicts": verdicts,
        "findings": findings,
        "quota": quota,
        "steps": steps,
        "current": {"entry": current.get("entry", ""), "stage": current.get("stage", "")},
        "flagged": flagged[:50],
        "sandbox": sandbox,
        "table": table[:1000],
        "log": log,
        "selftest": state.get_meta("selftest"),
        "refresh_seconds": cfg.section("dashboard").get("refresh_seconds", 2),
    }


def create_app(cfg: Config):
    from fastapi import FastAPI
    from fastapi.responses import FileResponse, JSONResponse

    app = FastAPI(title="jam-triage", docs_url=None, redoc_url=None, openapi_url=None)
    state = State(cfg.state_db)

    @app.get("/api/status")
    def status():
        return JSONResponse(build_status(cfg, state), headers={"Cache-Control": "no-store"})

    @app.get("/")
    def index():
        return FileResponse(WEB_DIR / "index.html", headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                                       "script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:",
            "X-Content-Type-Options": "nosniff"})

    @app.get("/report")
    def report():
        p = cfg.out_dir / "report.html"
        if not p.is_file():
            return JSONResponse({"error": "no report yet; run `triage report`"}, status_code=404)
        return FileResponse(p, headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})

    return app


class DashboardServer:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.thread: threading.Thread | None = None
        self.server = None

    def start(self) -> str:
        import uvicorn

        sec = self.cfg.section("dashboard")
        host = str(sec.get("host", "127.0.0.1"))
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise SystemExit("Refusing to bind the dashboard to a non-loopback address. Use 127.0.0.1.")
        port = int(sec.get("port", 8787))
        config = uvicorn.Config(create_app(self.cfg), host=host, port=port, log_level="warning", access_log=False)
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True, name="dashboard")
        self.thread.start()
        return f"http://{host}:{port}"

    def stop(self) -> None:
        if self.server:
            self.server.should_exit = True
