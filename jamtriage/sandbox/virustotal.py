"""`triage sandbox`: run every consenting entry through VirusTotal's own sandboxes, in batch.

    triage sandbox plan      what would be uploaded, how many requests that takes, how many days of budget
    triage sandbox upload    upload each entry's main executable (skips files VirusTotal already has)
    triage sandbox collect   later: fetch the fresh 70-engine scan + sandbox behaviour, merge, re-score
    triage sandbox status    where every entry stands

Uploading makes the file PUBLIC on VirusTotal. Each entry needs consent: the "public upload consent"
column in out/report.xlsx, or `consent_all = true` under [sandbox] when every entrant agreed in the
jam rules. Nothing here runs by default: only these explicit commands and `triage analyze --sandbox` do. Every request goes through the shared VirusTotal limiter, so pacing (4/min) and the daily
and monthly budgets are respected together with the hash lookups; both commands stop cleanly when the
budget is spent and pick up where they left off on the next run.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from rich.console import Console
from rich.table import Table

from ..config import Config
from ..lookups import BudgetSpent, make_limiter, take
from ..lookups.services import RateLimited, ServiceError, VirusTotal
from ..models import Finding, Severity
from ..pipeline import local_path
from ..report import read_user_columns
from ..state import LookupCache, State, iso_now

VT_MAX_UPLOAD = 650 * 1024 * 1024        # VirusTotal API limit (with an upload URL)
VT_DIRECT_UPLOAD = 32 * 1024 * 1024      # above this an extra request fetches an upload URL
MAX_COLLECT_ATTEMPTS = 4                  # then "no sandbox report" (VirusTotal doesn't sandbox every file)
RETRY_AFTER = 2 * 3600                    # seconds between collect attempts for the same entry
CONSENT_WORDS = ("y", "yes", "true", "1", "x", "ok")

# Statuses: uploaded, known (VirusTotal already had the file), waiting (no behaviour yet),
# collected, no_report, skipped (with a note), error.


def allowed(cfg: Config) -> bool:
    """Sandboxing is opt-in per command; the self-test never uploads anything."""
    return not getattr(cfg, "selftest", False)


def _slot(lim) -> None:
    take(lim)


def _entries(cfg: Config, only: list[str] | None) -> list[dict]:
    out = []
    for p in sorted(cfg.results_dir.glob("*/local.json")):
        try:
            local = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not only or local.get("slug") in only:
            out.append(local)
    return out


def _target(cfg: Config, local: dict, max_bytes: int = VT_MAX_UPLOAD,
            limit_text: str = "VirusTotal's 650 MB upload limit") -> tuple[str, Path | None, str, str]:
    """(relative path, absolute path, sha256, skip reason) of the file to sandbox: the main executable."""
    from .detonate import _abs
    main = (local.get("info") or {}).get("main_exe") or ""
    if not main:
        return "", None, "", "no executable (web-only or no game binary)"
    rec = next((f for f in local.get("files", []) if f.get("path") == main), None)
    if not rec or not rec.get("sha256"):
        return main, None, "", "main executable not hashed"
    path = _abs(cfg, local, main)
    if not path.is_file():
        return main, None, rec["sha256"], "main executable missing on disk (quarantined?)"
    if rec.get("size", 0) > max_bytes:
        return main, path, rec["sha256"], f"larger than {limit_text}"
    return main, path, rec["sha256"], ""


def _consents(cfg: Config) -> tuple[bool, dict]:
    if cfg.section("sandbox").get("consent_all"):
        return True, {}
    return False, read_user_columns(cfg.out_dir / "report.xlsx")


def _has_consent(slug: str, all_ok: bool, user: dict) -> bool:
    return all_ok or (user.get(slug, {}).get("public upload consent", "").strip().lower() in CONSENT_WORDS)


def plan(cfg: Config, console: Console, only: list[str] | None = None) -> list[dict]:
    st, cache = State(cfg.state_db), LookupCache(cfg.cache_file)
    all_ok, user = _consents(cfg)
    rows = []
    for local in _entries(cfg, only):
        slug = local["slug"]
        rel, path, sha, why = _target(cfg, local)
        prev = st.sandbox_get(slug) or {}
        if prev.get("sha256") and sha and prev["sha256"] != sha:
            prev = {}                       # build changed: would be uploaded again
        if prev.get("status") in ("uploaded", "known", "waiting", "collected", "no_report"):
            action = f"done ({prev['status']})"
        elif why:
            action = f"skip: {why}"
        elif not _has_consent(slug, all_ok, user):
            action = "skip: no consent"
        elif ((cache.get(sha, "virustotal") or {}).get("found")):
            action = "known to VirusTotal: no upload needed"
        else:
            action = "upload"
        size = (path.stat().st_size if path and path.is_file() else 0)
        rows.append({"slug": slug, "file": rel, "sha256": sha, "size": size, "action": action})
    up = [r for r in rows if r["action"] == "upload"]
    known = [r for r in rows if r["action"].startswith("known")]
    upload_requests = sum(2 if r["size"] > VT_DIRECT_UPLOAD else 1 for r in up)
    collect_requests = 2 * (len(up) + len(known)
                            + sum(1 for r in rows if r["action"] in ("done (uploaded)", "done (known)",
                                                                     "done (waiting)")))
    lim = make_limiter(cfg, st, "virustotal")
    left = lim.remaining()
    t = Table(title="VirusTotal sandbox plan")
    for c in ("entry", "file", "size", "action"):
        t.add_column(c)
    for r in rows:
        t.add_row(r["slug"], r["file"].rsplit("/", 1)[-1], f"{r['size'] / 1e6:.1f} MB" if r["size"] else "",
                  r["action"])
    console.print(t)
    total = upload_requests + collect_requests
    per_day = lim.budget or 480
    console.print(f"Uploads: {len(up)} file(s), {upload_requests} request(s). Already on VirusTotal: {len(known)}. "
                  f"Collecting afterwards: about {collect_requests} request(s) (scan + behaviour per entry, "
                  f"more if a report isn't ready yet).")
    console.print(f"Total about {total} VirusTotal requests at {60 / lim.interval:g}/min "
                  f"(≈{total * lim.interval / 60:.0f} min of pacing). Budget left today: {left} of {per_day}; "
                  f"hash lookups share it. Expect about {max(1, -(-total // per_day))} day(s).")
    return rows


def upload_all(cfg: Config, console: Console, only: list[str] | None = None) -> int:
    from .detonate import _log_upload
    if not allowed(cfg):
        return 2
    key = cfg.key("VT_API_KEY")
    if not key:
        console.print("[red]VT_API_KEY is not set.[/]")
        return 3
    st, cache = State(cfg.state_db), LookupCache(cfg.cache_file)
    lim = make_limiter(cfg, st, "virustotal")
    vt = VirusTotal(key)
    all_ok, user = _consents(cfg)
    done = skipped = 0
    for local in _entries(cfg, only):
        slug = local["slug"]
        now_doing(st, slug, "VirusTotal sandbox: upload")
        prev = st.sandbox_get(slug) or {}
        rel, path, sha, why = _target(cfg, local)
        if prev and sha and prev.get("sha256") and prev["sha256"] != sha:
            prev = {}                       # the build changed since the last upload: start over for this entry
            st.sandbox_set(slug, status="", attempts=0, checked=0, uploaded=0, ref="", note="build changed")
        if prev.get("status") in ("uploaded", "known", "waiting", "collected", "no_report"):
            continue
        if why:
            st.sandbox_set(slug, file=rel, sha256=sha, status="skipped", note=why)
            skipped += 1
            continue
        if not _has_consent(slug, all_ok, user):
            st.sandbox_set(slug, file=rel, sha256=sha, status="skipped", note="no consent")
            skipped += 1
            continue
        if (cache.get(sha, "virustotal") or {}).get("found"):
            st.sandbox_set(slug, file=rel, sha256=sha, status="known", uploaded=time.time(), note="")
            console.print(f"{slug}: already on VirusTotal, no upload needed")
            continue
        size = path.stat().st_size
        try:
            for _ in range(2 if size > VT_DIRECT_UPLOAD else 1):
                _slot(lim)
            ref = vt.upload(path, size)
        except BudgetSpent as exc:
            console.print(f"[yellow]Stopping: VirusTotal {exc}. Run `triage sandbox upload` again later; "
                          f"finished entries are skipped.[/]")
            break
        except RateLimited:
            lim.pause(60)
            console.print(f"[yellow]{slug}: HTTP 429; stopping for now. Run it again later.[/]")
            break
        except (ServiceError, OSError) as exc:
            st.sandbox_set(slug, file=rel, sha256=sha, status="error", note=str(exc)[:300])
            console.print(f"[red]{slug}: upload failed: {exc}[/]")
            continue
        except Exception as exc:  # noqa: BLE001  network trouble: leave it for the next run
            console.print(f"[red]{slug}: upload failed ({type(exc).__name__}: {exc}); will retry next run[/]")
            continue
        st.sandbox_set(slug, file=rel, sha256=sha, status="uploaded", uploaded=time.time(), ref=ref, note="")
        _log_upload(cfg, slug, path, "virustotal", ref)
        done += 1
        console.print(f"{slug}: uploaded {path.name} ({size / 1e6:.1f} MB)")
    console.print(f"Uploaded {done} file(s); skipped {skipped}. Wait about "
                  f"{cfg.section('sandbox').get('min_age_minutes', 30)} minutes, then run "
                  f"`triage sandbox collect`.")
    return 0


def _verdict_findings(report: dict) -> list[Finding]:
    out = []
    for v in report.get("sandbox_verdicts") or []:
        cat, names, box = v.get("category", ""), v.get("names") or [], v.get("sandbox", "?")
        if cat == "malicious":
            out.append(Finding(rule="detonation.vt_sandbox_malicious",
                               severity=Severity.CRITICAL if names else Severity.HIGH,
                               title=f"Sandbox: VirusTotal's {box} sandbox says malicious"
                                     + (f" ({', '.join(names)})" if names else ""),
                               source="virustotal-sandbox"))
        elif cat == "suspicious":
            out.append(Finding(rule="detonation.vt_sandbox_suspicious", severity=Severity.MEDIUM,
                               title=f"Sandbox: VirusTotal's {box} sandbox says suspicious",
                               detail=", ".join(names), source="virustotal-sandbox"))
    return out


def collect_all(cfg: Config, console: Console, only: list[str] | None = None, force: bool = False,
                pipe=None) -> int:
    from .detonate import _vt_behaviour_texts, map_behaviour
    from ..pipeline import Pipeline
    if not allowed(cfg):
        return 2
    key = cfg.key("VT_API_KEY")
    if not key:
        console.print("[red]VT_API_KEY is not set.[/]")
        return 3
    pipe = pipe or Pipeline(cfg, console)
    st, cache = pipe.state, pipe.cache          # one cache, so re-scoring sees the fresh scans
    lim = make_limiter(cfg, st, "virustotal")
    vt = VirusTotal(key)
    min_age = float(cfg.section("sandbox").get("min_age_minutes", 30)) * 60
    now = time.time()
    got = waiting = 0
    for row in st.sandbox_all():
        slug = row["slug"]
        if only and slug not in only:
            continue
        now_doing(st, slug, "VirusTotal sandbox: collect")
        if row["status"] not in ("uploaded", "known", "waiting") and not (force and row["status"] == "collected"):
            continue
        if row["status"] == "uploaded" and now - row["uploaded"] < min_age:
            waiting += 1
            continue
        if row["status"] == "waiting" and now - row["checked"] < RETRY_AFTER and not force:
            waiting += 1
            continue
        try:
            _slot(lim)
            report = vt.lookup(row["sha256"])            # fresh 70-engine scan of the uploaded file
            if report.get("found"):
                cache.put(row["sha256"], "virustotal", report)
            _slot(lim)
            summary = vt.behaviour_summary(row["sha256"])
        except BudgetSpent as exc:
            console.print(f"[yellow]Stopping: VirusTotal {exc}. Run `triage sandbox collect` again later.[/]")
            break
        except RateLimited:
            lim.pause(60)
            console.print("[yellow]HTTP 429; stopping for now. Run it again later.[/]")
            break
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]{slug}: {type(exc).__name__}: {exc}; will retry next run[/]")
            continue
        attempts = row["attempts"] + 1
        findings = _verdict_findings(report)
        has_behaviour = bool(summary) and any(summary.get(k) for k in summary)
        if has_behaviour:
            findings += [f for f in map_behaviour(_vt_behaviour_texts(summary), None, [], "virustotal-sandbox")
                         if f.rule != "detonation.quiet"]
        if not has_behaviour and not findings and attempts < MAX_COLLECT_ATTEMPTS:
            st.sandbox_set(slug, status="waiting", checked=time.time(), attempts=attempts)
            waiting += 1
            console.print(f"{slug}: no sandbox report yet (attempt {attempts}/{MAX_COLLECT_ATTEMPTS})")
            continue
        status = "collected" if (has_behaviour or findings) else "no_report"
        if status == "no_report":
            findings.append(Finding(rule="detonation.no_report", severity=Severity.INFO,
                                    title="VirusTotal didn't run this file in a sandbox (common for game "
                                          "binaries); nothing was learned from detonation",
                                    source="virustotal-sandbox"))
        out_dir = cfg.data_dir / "detonation" / slug
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "virustotal-file.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
        if summary:
            (out_dir / "virustotal-behaviour.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
        lp = local_path(cfg, slug)
        local = json.loads(lp.read_text(encoding="utf-8"))
        # Only ever add findings: a quiet sandbox run never upgrades a verdict.
        local["findings"] = [f for f in local.get("findings", []) if f.get("source") != "virustotal-sandbox"]
        local["findings"] += [f.to_dict() for f in findings]
        local.setdefault("info", {}).setdefault("sandbox", {})["virustotal"] = {
            "when": iso_now(), "file": row["file"], "status": status}
        lp.write_text(json.dumps(local, indent=1), encoding="utf-8")
        res = pipe.score(slug, local)
        st.sandbox_set(slug, status=status, checked=time.time(), attempts=attempts)
        got += 1
        flags = [f for f in findings if f.severity >= Severity.MEDIUM]
        console.print(f"{slug}: {status}; {len(flags)} sandbox finding(s); verdict {res['verdict']}")
    console.print(f"Collected {got} entr{'y' if got == 1 else 'ies'}; {waiting} still waiting "
                  f"(run `triage sandbox collect` again later). Then `triage report`.")
    return 0


def status(cfg: Config, console: Console, providers: tuple[str, ...] = ("virustotal", "hybrid")) -> None:
    from ..lookups import hybrid_limiters
    st = State(cfg.state_db)
    names = {"virustotal": "VirusTotal", "hybrid": "Hybrid Analysis"}
    for prov in providers:
        rows = st.sandbox_all(prov)
        t = Table(title=f"{names[prov]} sandbox status")
        for c in ("entry", "status", "attempts", "note"):
            t.add_column(c)
        for r in rows:
            t.add_row(r["slug"], r["status"], str(r["attempts"]), r["note"])
        console.print(t)
        counts: dict[str, int] = {}
        for r in rows:
            counts[r["status"]] = counts.get(r["status"], 0) + 1
        console.print(", ".join(f"{k}: {v}" for k, v in sorted(counts.items())) or "nothing uploaded yet")
    vt = make_limiter(cfg, st, "virustotal")
    _, subs = hybrid_limiters(cfg, st)
    console.print(f"VirusTotal requests left today: {vt.remaining()} · Hybrid Analysis submissions left today: "
                  f"{subs.remaining()}")


PROVIDERS = ("virustotal", "hybrid")


def now_doing(st: State, slug: str, stage: str) -> None:
    """Show the sandbox step on the dashboard's "now:" line (also for a standalone `triage sandbox`)."""
    st.set_meta("current", {"entry": slug, "stage": stage})


def available(cfg: Config) -> list[str]:
    """Sandboxes that can run: VirusTotal needs VT_API_KEY, Hybrid Analysis HA_API_KEY."""
    out = []
    if cfg.key("VT_API_KEY"):
        out.append("virustotal")
    if cfg.key("HA_API_KEY"):
        out.append("hybrid")
    return out


def run(cfg: Config, console: Console, action: str, providers: list[str], only: list[str] | None = None,
        force: bool = False, pipe=None) -> int:
    """Run one action (plan/upload/collect) on each requested sandbox."""
    import sys

    from . import hybrid
    mods = {"virustotal": sys.modules[__name__], "hybrid": hybrid}
    rc = 0
    for prov in providers:
        mod = mods[prov]
        if action == "plan":
            mod.plan(cfg, console, only)
        elif action == "upload":
            rc = max(rc, mod.upload_all(cfg, console, only))
        elif action == "collect":
            rc = max(rc, mod.collect_all(cfg, console, only, force=force, pipe=pipe))
    if action != "plan":
        State(cfg.state_db).set_meta("current", {"entry": "", "stage": ""})
    return rc
