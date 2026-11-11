"""Batch Hybrid Analysis (CrowdStrike Falcon Sandbox) runs for every consenting entry.

Driven by `triage sandbox ... --provider hybrid` and by `triage analyze --sandbox` (together with the
VirusTotal sandbox). Same model as the VirusTotal sandbox (virustotal.py): `upload` submits entries that haven't been submitted yet,
`collect` later fetches finished reports, merges them and re-scores; both are resumable.

Limits: every request goes through the "hybrid" limiter (requests/minute) and every submission also
through "hybrid-submit" (daily submissions, 95 by default under the free tier's 100). When the day's
submissions are used up the command stops and continues on the next run.

Uploads are PUBLIC on hybrid-analysis.com and need the same consent as the VirusTotal sandbox.
"""
from __future__ import annotations

import json
import time

from rich.console import Console
from rich.table import Table

from ..config import Config
from ..lookups import BudgetSpent, hybrid_limiters
from ..lookups.services import RateLimited, ServiceError
from ..models import Finding, Severity
from ..pipeline import local_path
from ..state import State, iso_now
from .virustotal import _consents, _entries, _has_consent, _target, allowed, now_doing

PROVIDER = "hybrid"
SOURCE = "hybrid-sandbox"
RETRY_AFTER = 20 * 60          # seconds between state checks for the same job
MAX_ATTEMPTS = 24              # then "no report" (the job never finished)
DONE = ("submitted", "waiting", "collected", "no_report")


def _client(cfg: Config, state: State):
    from .detonate import HybridClient
    return HybridClient(cfg.key("HA_API_KEY") or "", int(cfg.section("hybridanalysis").get("environment_id", 160)),
                        hybrid_limiters(cfg, state))


def _max_bytes(cfg: Config) -> int:
    return int(float(cfg.section("hybridanalysis").get("max_upload_mb", 100)) * 1024 * 1024)


def plan(cfg: Config, console: Console, only: list[str] | None = None) -> list[dict]:
    st = State(cfg.state_db)
    all_ok, user = _consents(cfg)
    rows = []
    for local in _entries(cfg, only):
        slug = local["slug"]
        rel, path, sha, why = _target(cfg, local, _max_bytes(cfg), "the Hybrid Analysis upload limit setting")
        prev = st.sandbox_get(slug, PROVIDER) or {}
        if prev.get("sha256") and sha and prev["sha256"] != sha:
            prev = {}
        if prev.get("status") in DONE:
            action = f"done ({prev['status']})"
        elif why:
            action = f"skip: {why}"
        elif not _has_consent(slug, all_ok, user):
            action = "skip: no consent"
        else:
            action = "submit"
        rows.append({"slug": slug, "file": rel, "action": action})
    subs = sum(1 for r in rows if r["action"] == "submit")
    _, sub_lim = hybrid_limiters(cfg, st)
    t = Table(title="Hybrid Analysis plan")
    for c in ("entry", "file", "action"):
        t.add_column(c)
    for r in rows:
        t.add_row(r["slug"], r["file"].rsplit("/", 1)[-1], r["action"])
    console.print(t)
    per_day = sub_lim.budget or 95
    console.print(f"Submissions: {subs}. Daily limit {per_day} (left today: {sub_lim.remaining()}), so about "
                  f"{max(1, -(-subs // per_day)) if subs else 0} day(s). Collecting: about 2 requests per entry "
                  f"(state + report), more while jobs are queued.")
    return rows


def upload_all(cfg: Config, console: Console, only: list[str] | None = None) -> int:
    from .detonate import _log_upload, hybrid_sample
    if not allowed(cfg):
        return 2
    if not cfg.key("HA_API_KEY"):
        console.print("[yellow]Hybrid Analysis: HA_API_KEY is not set; skipped.[/]")
        return 3
    st = State(cfg.state_db)
    client = _client(cfg, st)
    try:
        client.require_submit()
    except ServiceError as exc:
        console.print(f"[yellow]Hybrid Analysis skipped: {exc}[/]")
        return 3
    except Exception as exc:  # noqa: BLE001  can't check the key: try the submissions anyway
        console.print(f"[dim]Hybrid Analysis: couldn't check the key's level ({type(exc).__name__}).[/]")
    all_ok, user = _consents(cfg)
    done = skipped = 0
    for local in _entries(cfg, only):
        slug = local["slug"]
        now_doing(st, slug, "Hybrid Analysis sandbox: submit")
        prev = st.sandbox_get(slug, PROVIDER) or {}
        rel, path, sha, why = _target(cfg, local, _max_bytes(cfg), "the Hybrid Analysis upload limit setting")
        if prev and sha and prev.get("sha256") and prev["sha256"] != sha:
            prev = {}
            st.sandbox_set(slug, PROVIDER, status="", attempts=0, checked=0, uploaded=0, ref="",
                           note="build changed")
        if prev.get("status") in DONE:
            continue
        if why or not _has_consent(slug, all_ok, user):
            st.sandbox_set(slug, PROVIDER, file=rel, sha256=sha, status="skipped", note=why or "no consent")
            skipped += 1
            continue
        out_dir = cfg.data_dir / "detonation" / slug
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            sample = hybrid_sample(cfg, local, rel, out_dir)
            job = client.submit(sample)
        except BudgetSpent as exc:
            console.print(f"[yellow]Hybrid Analysis: stopping ({exc}). Run it again tomorrow; submitted entries "
                          f"are skipped.[/]")
            break
        except RateLimited as exc:
            client.req_lim.pause(min(exc.retry_after or 60, 600))
            console.print("[yellow]Hybrid Analysis: HTTP 429; stopping for now.[/]")
            break
        except ServiceError as exc:
            if exc.fatal:
                console.print(f"[red]Hybrid Analysis: {exc}[/]")
                return 3
            st.sandbox_set(slug, PROVIDER, file=rel, sha256=sha, status="error", note=str(exc)[:300])
            console.print(f"[red]{slug}: Hybrid Analysis submission failed: {exc}[/]")
            continue
        except Exception as exc:  # noqa: BLE001  network trouble: retry next run
            console.print(f"[red]{slug}: Hybrid Analysis submission failed ({type(exc).__name__}: {exc})[/]")
            continue
        st.sandbox_set(slug, PROVIDER, file=rel, sha256=sha, status="submitted", uploaded=time.time(), ref=job,
                       note="")
        _log_upload(cfg, slug, sample, "hybrid-analysis", job)
        done += 1
        console.print(f"{slug}: submitted to Hybrid Analysis (job {job})")
    console.print(f"Hybrid Analysis: submitted {done}; skipped {skipped}.")
    return 0


def collect_all(cfg: Config, console: Console, only: list[str] | None = None, force: bool = False,
                pipe=None) -> int:
    from ..pipeline import Pipeline
    from .detonate import hybrid_findings
    if not allowed(cfg):
        return 2
    if not cfg.key("HA_API_KEY"):
        return 3
    pipe = pipe or Pipeline(cfg, console)
    st = pipe.state
    client = _client(cfg, st)
    min_age = float(cfg.section("sandbox").get("min_age_minutes", 30)) * 60
    now = time.time()
    got = waiting = 0
    for row in st.sandbox_all(PROVIDER):
        slug = row["slug"]
        if only and slug not in only:
            continue
        now_doing(st, slug, "Hybrid Analysis sandbox: collect")
        if row["status"] not in ("submitted", "waiting") and not (force and row["status"] == "collected"):
            continue
        if row["status"] == "submitted" and now - row["uploaded"] < min_age:
            waiting += 1
            continue
        if row["status"] == "waiting" and now - row["checked"] < RETRY_AFTER and not force:
            waiting += 1
            continue
        attempts = row["attempts"] + 1
        try:
            state = client.state(row["ref"])
            summary = client.summary(row["ref"]) if state == "SUCCESS" else None
        except BudgetSpent as exc:
            console.print(f"[yellow]Hybrid Analysis: stopping ({exc}).[/]")
            break
        except RateLimited as exc:
            client.req_lim.pause(min(exc.retry_after or 60, 600))
            console.print("[yellow]Hybrid Analysis: HTTP 429; stopping for now.[/]")
            break
        except ServiceError as exc:
            if exc.fatal:
                console.print(f"[red]Hybrid Analysis: {exc}[/]")
                return 3
            console.print(f"[red]{slug}: {exc}; will retry[/]")
            continue
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]{slug}: {type(exc).__name__}: {exc}; will retry[/]")
            continue
        if state == "ERROR":
            st.sandbox_set(slug, PROVIDER, status="error", checked=time.time(), attempts=attempts,
                           note="Hybrid Analysis reported an error for this job")
            console.print(f"{slug}: Hybrid Analysis job failed")
            continue
        if summary is None:
            if attempts < MAX_ATTEMPTS:
                st.sandbox_set(slug, PROVIDER, status="waiting", checked=time.time(), attempts=attempts,
                               note=state or "")
                waiting += 1
                continue
            findings = [Finding(rule="detonation.no_report", severity=Severity.INFO,
                                title="Hybrid Analysis didn't finish this job; nothing was learned from it",
                                source=SOURCE)]
            status = "no_report"
        else:
            findings = hybrid_findings(summary, SOURCE)
            status = "collected"
            out_dir = cfg.data_dir / "detonation" / slug
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "hybrid-summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
        lp = local_path(cfg, slug)
        local = json.loads(lp.read_text(encoding="utf-8"))
        # Only ever add findings: a quiet sandbox run never upgrades a verdict.
        local["findings"] = [f for f in local.get("findings", []) if f.get("source") != SOURCE]
        local["findings"] += [f.to_dict() for f in findings]
        local.setdefault("info", {}).setdefault("sandbox", {})["hybrid"] = {
            "when": iso_now(), "file": row["file"], "status": status, "job": row["ref"],
            "verdict": (summary or {}).get("verdict"), "threat_score": (summary or {}).get("threat_score")}
        lp.write_text(json.dumps(local, indent=1), encoding="utf-8")
        res = pipe.score(slug, local)
        st.sandbox_set(slug, PROVIDER, status=status, checked=time.time(), attempts=attempts)
        got += 1
        flags = [f for f in findings if f.severity >= Severity.MEDIUM]
        console.print(f"{slug}: Hybrid Analysis {status}; {len(flags)} finding(s); verdict {res['verdict']}")
    console.print(f"Hybrid Analysis: collected {got}; {waiting} still running or queued "
                  f"(run `triage sandbox collect` again later).")
    return 0


def status_rows(cfg: Config) -> list[dict]:
    return State(cfg.state_db).sandbox_all(PROVIDER)
