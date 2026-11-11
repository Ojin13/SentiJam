"""Opt-in cloud actions on one entry: `triage detonate` (Hybrid Analysis run and/or the VirusTotal
behaviour report) and `triage upload` (VirusTotal). The batch version for every entry is `triage sandbox`.

Both make the file PUBLIC. They refuse unless the entry is marked as consenting to public uploads
(the "public upload consent" column in out/report.xlsx) or --confirm-public is passed.
Every upload is logged to data/uploads.jsonl.
"""
from __future__ import annotations

import json
import re
import time
import zipfile
from pathlib import Path

import requests
from rich.console import Console

from ..config import Config
from ..lookups.services import RateLimited, ServiceError, VirusTotal
from ..models import Finding, Severity
from ..pipeline import local_path, result_path
from ..report import consent_for
from ..state import iso_now

BROWSER_RX = re.compile(r"login data|local state|\\cookies|cookies\.sqlite|logins\.json|key4\.db|"
                        r"local storage\\leveldb|\\discord", re.I)
EXFIL_RX = re.compile(r"discord(app)?\.com/api/webhooks|api\.telegram\.org|pastebin\.com|paste\.ee|rentry\.co|"
                      r"https?://\d{1,3}(\.\d{1,3}){3}", re.I)
SHELL_RX = re.compile(r"\b(powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32)\b", re.I)
AUTOSTART_RX = re.compile(r"currentversion\\run|\\start menu\\programs\\startup|schtasks|scheduled task", re.I)
VM_RX = re.compile(r"virtual ?machine|vmware|virtualbox|vbox|sandbox|anti-?vm|debugger|anti-?debug", re.I)
DROP_RX = re.compile(r"drops? (and runs|executable)|dropped|executes dropped|creates? .*\.exe", re.I)


class Refused(Exception):
    pass


def _log_upload(cfg: Config, entry: str, file: Path, where: str, ref: str) -> None:
    p = cfg.data_dir / "uploads.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"when": iso_now(), "entry": entry, "file": str(file), "service": where, "ref": ref}) + "\n")


def _require_consent(cfg: Config, entry: str, confirm_public: bool) -> None:
    if confirm_public or consent_for(cfg, entry):
        return
    raise Refused(f"{entry} is not marked as consenting to public uploads. Set the 'public upload consent' "
                  f"column to yes in out/report.xlsx, or pass --confirm-public if your jam rules allow it.")


def _load(cfg: Config, entry: str) -> tuple[dict, dict]:
    lp, rp = local_path(cfg, entry), result_path(cfg, entry)
    if not lp.is_file():
        raise Refused(f"No analysis for {entry!r}; run `triage analyze` first.")
    local = json.loads(lp.read_text(encoding="utf-8"))
    result = json.loads(rp.read_text(encoding="utf-8")) if rp.is_file() else {}
    return local, result


def _abs(cfg: Config, local: dict, rel: str) -> Path:
    area, _, rest = rel.partition("/")
    base = {"builds": Path(local["entry"]["root"]), "unpacked": cfg.unpacked_dir / local["slug"],
            "unwrapped": cfg.unwrapped_dir / local["slug"]}[area]
    return base / rest


# --------------------------------------------------------------------------- upload

def _vt_slot(cfg: Config, n: int = 1) -> None:
    """Take n VirusTotal request slots from the shared limiter (same pacing and budget as hash lookups)."""
    from ..lookups import make_limiter
    from ..state import State
    lim = make_limiter(cfg, State(cfg.state_db), "virustotal")
    for _ in range(n):
        if not lim.acquire(max_wait=120):
            raise Refused(f"VirusTotal: {lim.last_refusal or 'no request slot'}; try again later.")


class _Poller:
    """Polling with a growing interval and a hard cap on the number of requests."""

    def __init__(self, first: float, longest: float = 120, max_polls: int = 60):
        self.delay, self.longest, self.left = first, longest, max_polls

    def wait(self) -> bool:
        if self.left <= 0:
            return False
        self.left -= 1
        time.sleep(self.delay)
        self.delay = min(self.delay * 1.5, self.longest)
        return True


def upload(cfg: Config, entry: str, file: str, confirm_public: bool, console: Console | None = None) -> int:
    console = console or Console()
    _require_consent(cfg, entry, confirm_public)
    key = cfg.key("VT_API_KEY")
    if not key:
        raise Refused("VT_API_KEY is not set.")
    local, _ = _load(cfg, entry)
    path = Path(file)
    if not path.is_absolute():
        match = next((f for f in local["files"] if f["path"] == file or f["path"].endswith("/" + file)), None)
        if not match:
            raise Refused(f"{file!r} is not a file of {entry}. Use a path from the report, e.g. {local['info'].get('main_exe')}")
        path = _abs(cfg, local, match["path"])
    vt = VirusTotal(key)
    _vt_slot(cfg, 2 if path.stat().st_size > 32 * 1024 * 1024 else 1)   # shares the lookups' pacing and budget
    analysis_id = vt.upload(path, path.stat().st_size)
    _log_upload(cfg, entry, path, "virustotal", analysis_id)
    console.print(f"Uploaded {path.name} to VirusTotal (analysis {analysis_id}). Logged in data/uploads.jsonl.")
    console.print("Results usually take a few minutes; `triage recheck` will pick them up.")
    return 0


# --------------------------------------------------------------------------- behaviour -> findings

def map_behaviour(texts: list[str], score: float | None, families: list[str], source: str) -> list[Finding]:
    """Turn sandbox output (signature names, process command lines, IOCs, file paths) into findings."""
    out: list[Finding] = []
    blob = "\n".join(t for t in texts if t)
    while "\\\\" in blob:            # JSON-encoded Windows paths: C:\\Users -> C:\Users
        blob = blob.replace("\\\\", "\\")

    def add(rule, sev, title, detail=""):
        out.append(Finding(rule=f"detonation.{rule}", severity=sev, title=f"Sandbox: {title}", detail=detail[:300],
                           source=source))

    if families or (score is not None and score >= 8):
        add("family", Severity.CRITICAL, "known malware family or high score",
            f"families: {', '.join(families) or '-'}; score {score}")
    for rx, rule, sev, title in ((BROWSER_RX, "browser_data", Severity.CRITICAL, "reads browser profile or Discord files"),
                                 (EXFIL_RX, "exfil", Severity.HIGH, "traffic to a webhook, bot API, paste site or raw IP"),
                                 (SHELL_RX, "shell", Severity.HIGH, "starts a shell or script host"),
                                 (AUTOSTART_RX, "autostart", Severity.HIGH, "writes autostart entries"),
                                 (DROP_RX, "dropper", Severity.HIGH, "drops and runs another executable"),
                                 (VM_RX, "anti_vm", Severity.MEDIUM, "checks for virtual machines or debuggers")):
        m = rx.search(blob)
        if m:
            line = next((t for t in blob.splitlines() if rx.search(t)), m.group(0))
            add(rule, sev, title, line)
    if not blob.strip() and not families:
        add("quiet", Severity.INFO, "game exited at once with no activity (missing GPU, or evasion)")
    return out


def _vt_behaviour_texts(summary: dict) -> list[str]:
    texts = []
    for k in ("processes_created", "command_executions", "files_opened", "files_written", "files_dropped",
              "registry_keys_set", "dns_lookups", "ip_traffic", "http_conversations", "mitre_attack_techniques",
              "signature_matches"):
        for item in summary.get(k) or []:
            texts.append(json.dumps(item) if isinstance(item, dict) else str(item))
    return texts


# --------------------------------------------------------------------------- Hybrid Analysis

class HybridClient:
    """Hybrid Analysis (CrowdStrike Falcon Sandbox) API v2. With limiters, every request takes a slot from
    the shared requests limiter and every submission also from the daily submissions limiter."""
    BASE = "https://www.hybrid-analysis.com/api/v2"

    def __init__(self, key: str, env_id: int, limiters: tuple | None = None):
        self.env = env_id
        self.req_lim, self.sub_lim = limiters or (None, None)
        self.s = requests.Session()
        self.s.headers.update({"api-key": key, "User-Agent": "Falcon Sandbox", "accept": "application/json"})

    def _call(self, method: str, url: str, **kw) -> requests.Response:
        from ..lookups import take
        if self.req_lim is not None:
            take(self.req_lim)
        r = self.s.request(method, url, **kw)
        if r.status_code == 429:
            raise RateLimited(float(r.headers.get("Retry-After") or 60), "Hybrid Analysis 429")
        if r.status_code == 401:
            raise ServiceError("Hybrid Analysis 401: check HA_API_KEY", fatal=True)
        if r.status_code == 403:
            text = r.text[:300]
            if any(w in text.lower() for w in ("quota", "limit", "exceeded")):
                from ..lookups import BudgetSpent
                raise BudgetSpent(f"Hybrid Analysis quota: {text}")
            raise ServiceError(f"Hybrid Analysis 403: {text}", fatal=True)
        return r

    RESTRICTED_HELP = ("your Hybrid Analysis API key is 'restricted' (new free accounts), which can't submit "
                       "files. Upgrade it once: hybrid-analysis.com > Profile > API key > 'Upgrade API key' "
                       "(a short vetting form; use your full real name or organisation)")

    def auth_level(self) -> str:
        """The key's authorisation level: restricted, default, elevated or super ("" if unknown)."""
        r = self._call("GET", f"{self.BASE}/key/current", timeout=60)
        return str(r.json().get("auth_level_name") or "") if r.status_code == 200 else ""

    def require_submit(self) -> None:
        """Fail early, with the fix, when the key can't submit (the API answers a restricted key's
        submission with a bare 404)."""
        if self.auth_level() == "restricted":
            raise ServiceError(self.RESTRICTED_HELP, fatal=True)

    def submit(self, path: Path) -> str:
        from ..lookups import take
        if self.sub_lim is not None:
            take(self.sub_lim, max_wait=120)
        with open(path, "rb") as fh:
            r = self._call("POST", f"{self.BASE}/submit/file", files={"file": (path.name, fh)},
                           data={"environment_id": str(self.env)}, timeout=600)
        if r.status_code >= 400:
            raise ServiceError(f"Hybrid Analysis HTTP {r.status_code}: {r.text[:300]}")
        return str(r.json()["job_id"])

    def state(self, job: str) -> str:
        r = self._call("GET", f"{self.BASE}/report/{job}/state", timeout=60)
        return (r.json().get("state") or "") if r.status_code == 200 else ""

    def summary(self, job: str) -> dict:
        r = self._call("GET", f"{self.BASE}/report/{job}/summary", timeout=120)
        if r.status_code >= 400:
            raise ServiceError(f"Hybrid Analysis HTTP {r.status_code}")
        return r.json()


def hybrid_findings(summ: dict, source: str) -> list[Finding]:
    """Map a Hybrid Analysis report summary to findings. Only signatures Hybrid Analysis itself rates
    suspicious or malicious are read (its informational ones fire on almost every program)."""
    sigs = [s for s in (summ.get("signatures") or []) if isinstance(s, dict) and int(s.get("threat_level") or 0) >= 1]
    texts = [json.dumps(summ.get(k)) for k in ("processes", "domains", "hosts", "extracted_files", "mitre_attcks")]
    texts += [" ".join(str(s.get(k, "")) for k in ("name", "description", "category")) for s in sigs]
    ts = summ.get("threat_score")
    fam = [summ["vx_family"]] if summ.get("vx_family") else []
    out = [f for f in map_behaviour(texts, (ts / 10) if isinstance(ts, (int, float)) else None, fam, source)
           if f.rule != "detonation.quiet"]
    verdict = str(summ.get("verdict") or "").lower()
    if verdict == "malicious" and not any(f.severity >= Severity.CRITICAL for f in out):
        out.append(Finding(rule="detonation.hybrid_malicious", severity=Severity.HIGH,
                           title="Sandbox: Hybrid Analysis verdict is malicious",
                           detail=f"threat score {ts}", source=source))
    elif verdict == "suspicious":
        out.append(Finding(rule="detonation.hybrid_suspicious", severity=Severity.MEDIUM,
                           title="Sandbox: Hybrid Analysis verdict is suspicious",
                           detail=f"threat score {ts}", source=source))
    return out


def hybrid_sample(cfg: Config, local: dict, main_rel: str, out_dir: Path) -> Path:
    """What to submit: the main exe (default, known to work) or, with [hybridanalysis] upload = "folder",
    the exe zipped with its neighbouring files (untested: it isn't documented which file Hybrid Analysis
    runs from inside a zip)."""
    if str(cfg.section("hybridanalysis").get("upload", "exe")) == "folder":
        return _package(cfg, local, main_rel, out_dir)
    return _abs(cfg, local, main_rel)


# --------------------------------------------------------------------------- detonate

def _package(cfg: Config, local: dict, main_rel: str, out_dir: Path) -> Path:
    """Zip the main executable with its sibling files (what the game needs to start), capped at 200 MB."""
    main = _abs(cfg, local, main_rel)
    folder = main.parent
    out = out_dir / f"{local['slug']}-sample.zip"
    total = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(main, main.name)
        for p in sorted(folder.rglob("*")):
            if p.is_file() and p != main and not p.is_symlink():
                total += p.stat().st_size
                if total > 200 * 1024 * 1024:
                    break
                zf.write(p, p.relative_to(folder).as_posix())
    return out


def detonate(cfg: Config, entry: str, confirm_public: bool, console: Console | None = None,
             file: str | None = None, poll_seconds: int = 20) -> int:
    console = console or Console()
    _require_consent(cfg, entry, confirm_public)
    local, result = _load(cfg, entry)
    if result.get("verdict") not in ("Review", "Disqualify", None):
        console.print(f"[yellow]{entry} is '{result.get('verdict')}', not Review. Detonation is meant for Review "
                      f"entries; continuing because you asked explicitly.[/]")
    sec = cfg.section("detonation")
    main_rel = file or local.get("info", {}).get("main_exe")
    if not main_rel:
        raise Refused(f"{entry} has no main executable to detonate; pass --file <path from the report>.")
    out_dir = cfg.data_dir / "detonation" / entry
    out_dir.mkdir(parents=True, exist_ok=True)
    sample = hybrid_sample(cfg, local, main_rel, out_dir)
    timeout = int(sec.get("timeout_seconds", 300))
    findings: list[Finding] = []
    providers: list[str] = []

    ha_key = cfg.key("HA_API_KEY")
    done = False
    if ha_key:
        from ..lookups import BudgetSpent, hybrid_limiters
        from ..state import State
        client = HybridClient(ha_key, int(cfg.section("hybridanalysis").get("environment_id", 160)),
                              hybrid_limiters(cfg, State(cfg.state_db)))
        try:
            client.require_submit()
            job = client.submit(sample)
            _log_upload(cfg, entry, sample, "hybrid-analysis", job)
            console.print(f"Submitted to Hybrid Analysis as {job}; polling…")
            deadline = time.time() + timeout + 3600
            poll = _Poller(max(poll_seconds, 30))
            time.sleep(min(timeout, 120))
            while time.time() < deadline and client.state(job) not in ("SUCCESS", "ERROR"):
                if not poll.wait():
                    break
            summ = client.summary(job)
            (out_dir / "hybrid-summary.json").write_text(json.dumps(summ, indent=1), encoding="utf-8")
            findings += hybrid_findings(summ, "hybrid-analysis")
            providers.append("hybrid-analysis")
            done = True
        except (ServiceError, RateLimited, BudgetSpent, requests.RequestException, KeyError) as exc:
            console.print(f"[yellow]Hybrid Analysis failed: {exc}[/]")

    # VirusTotal behaviour summary if the main file's hash is known there.
    vt_key = cfg.key("VT_API_KEY")
    main_sha = next((f["sha256"] for f in local["files"] if f["path"] == main_rel), "")
    if vt_key and main_sha:
        try:
            _vt_slot(cfg)
            summ = VirusTotal(vt_key).behaviour_summary(main_sha)
            if summ:
                (out_dir / "virustotal-behaviour.json").write_text(json.dumps(summ, indent=1), encoding="utf-8")
                findings += [f for f in map_behaviour(_vt_behaviour_texts(summ), None, [], "virustotal-behaviour")
                             if f.rule != "detonation.quiet"]
                providers.append("virustotal")
                done = True
        except (ServiceError, RateLimited, requests.RequestException, Refused) as exc:
            console.print(f"[dim]VirusTotal behaviour: {exc}[/]")

    if not done:
        console.print("[red]No sandbox result.[/] VirusTotal has no behaviour report for this file yet. Upload it "
                      "first (`triage upload`, or the batch `triage sandbox`), or set HA_API_KEY for Hybrid Analysis.")
        return 1
    # Merge into the entry's saved results. A clean run never upgrades a verdict: we only ever add findings.
    # (Only this command's own earlier results are replaced; `triage sandbox` results are kept.)
    local["findings"] = [f for f in local["findings"]
                         if f.get("source") not in ("hybrid-analysis", "virustotal-behaviour")]
    local["findings"] += [f.to_dict() for f in findings]
    local.setdefault("info", {})["detonation"] = {"when": iso_now(), "provider": "+".join(providers),
                                                  "sample": sample.name}
    local_path(cfg, entry).write_text(json.dumps(local, indent=1), encoding="utf-8")
    from ..pipeline import Pipeline
    res = Pipeline(cfg, console).score(entry, local)
    for f in findings:
        console.print(f"  [{f.severity.label.upper()}] {f.title}  {f.detail}")
    console.print(f"Verdict for {entry}: [bold]{res['verdict']}[/] (raw reports in {out_dir})")
    return 0
