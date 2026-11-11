"""OS-dependent antivirus scan: Microsoft Defender (Windows), ClamAV (macOS/Linux), Defender for Mac if present."""
from __future__ import annotations

import re
import threading
from pathlib import Path

from ..models import Finding, Severity
from ..tools import which
from . import EntryContext, ToolError, run_tool

_update_lock = threading.Lock()
_updated: dict[str, str] = {}


def update_signatures(ctx: EntryContext, engine: str) -> str:
    """Run freshclam / MpCmdRun -SignatureUpdate once per process. Returns a status string."""
    if not ctx.cfg.section("antivirus").get("update_before_scan", True):
        return "skipped (disabled in config)"
    with _update_lock:
        if engine in _updated:
            return _updated[engine]
        status = "not attempted"
        try:
            if engine == "clamav":
                fc = which("freshclam")
                if fc:
                    p = run_tool([fc], timeout=600)
                    status = "ok" if p.returncode == 0 else f"failed (exit {p.returncode}): {(p.stderr or p.stdout).strip()[-200:]}"
                else:
                    status = "freshclam not found"
            elif engine == "defender":
                exe = ctx.tool("defender")
                p = run_tool([exe, "-SignatureUpdate"], timeout=900)
                status = "ok" if p.returncode == 0 else f"failed (exit {p.returncode})"
        except ToolError as exc:
            status = f"failed: {exc}"
        _updated[engine] = status
        return status


def parse_clamscan(output: str) -> list[tuple[str, str]]:
    hits = []
    for line in output.splitlines():
        m = re.match(r"^(.*): (.+) FOUND$", line.strip())
        if m:
            hits.append((m.group(1), m.group(2)))
    return hits


def parse_mpcmdrun(output: str) -> list[tuple[str, str]]:
    """Parse MpCmdRun text output: 'Threat : <name>' blocks followed by 'file : <path>' lines."""
    hits, threat = [], None
    for line in output.splitlines():
        m = re.match(r"^\s*Threat\s*:\s*(.+)$", line)
        if m:
            threat = m.group(1).strip()
            continue
        m = re.match(r"^\s*file\s*:\s*(.+)$", line, re.IGNORECASE)
        if m and threat:
            hits.append((m.group(1).strip(), threat))
    if threat and not hits:
        hits.append(("", threat))
    return hits


def parse_mdatp(output: str) -> list[tuple[str, str]]:
    hits = []
    for line in output.splitlines():
        m = re.search(r'"(?P<path>[^"]+)"\s.*?(?:threat|detected)[^"]*"?(?P<name>[\w:/.!-]+)?', line, re.IGNORECASE)
        if m and ("threat" in line.lower() or "detected" in line.lower()):
            hits.append((m.group("path"), m.group("name") or "threat"))
    m = re.search(r"(\d+)\s+threat\(s\) detected", output)
    if m and int(m.group(1)) > 0 and not hits:
        hits.append(("", f"{m.group(1)} threat(s) detected"))
    return hits


def _folders(ctx: EntryContext) -> list[Path]:
    return [d for d in (ctx.builds_root, ctx.unpacked_root, ctx.unwrapped_root) if d.exists()]


def _report(ctx: EntryContext, engine: str, hits: list[tuple[str, str]]) -> None:
    for path, name in hits:
        rel = ctx.relpath(Path(path)) if path else ""
        ctx.add(Finding(rule="av.detection", severity=Severity.HIGH, title=f"{engine} reports a threat",
                        file=rel, detail=name, source=engine.lower().replace(" ", "")))
    ctx.info.setdefault("av", {})[engine] = [n for _, n in hits] or ["clean"]


def scan_clamav(ctx: EntryContext, folders: list[Path] | None = None) -> None:
    exe = ctx.tool("clamav")
    if not exe:
        ctx.not_run("clamav", "clamscan not installed")
        return
    ctx.info["av_update"] = update_signatures(ctx, "clamav")
    timeout = int(ctx.cfg.section("antivirus").get("timeout_seconds", 1800))
    cmd = [exe, "-r", "-i", "--no-summary", "--stdout", "--max-filesize=2000M", "--max-scansize=4000M",
           *[str(f) for f in (folders or _folders(ctx))]]
    try:
        p = run_tool(cmd, timeout=timeout)
    except ToolError as exc:
        ctx.error("clamav", str(exc))
        return
    hits = parse_clamscan(p.stdout)
    if p.returncode not in (0, 1) and not hits:
        ctx.error("clamav", f"exit {p.returncode}: {(p.stderr or p.stdout).strip()[-200:]}")
        return
    _report(ctx, "ClamAV", hits)
    ctx.checks["clamav"] = "ok"


def scan_defender(ctx: EntryContext, folders: list[Path] | None = None) -> None:
    exe = ctx.tool("defender")
    if not exe:
        ctx.not_run("defender", "MpCmdRun.exe not found")
        return
    ctx.info["av_update"] = update_signatures(ctx, "defender")
    timeout = int(ctx.cfg.section("antivirus").get("timeout_seconds", 1800))
    hits: list[tuple[str, str]] = []
    for folder in folders or _folders(ctx):
        try:
            p = run_tool([exe, "-Scan", "-ScanType", "3", "-File", str(folder), "-DisableRemediation"], timeout=timeout)
        except ToolError as exc:
            ctx.error("defender", str(exc))
            return
        # Exit code 2 means "threat found OR scan error": parse the text, don't trust the code.
        found = parse_mpcmdrun(p.stdout + "\n" + p.stderr)
        if p.returncode not in (0, 2) and not found:
            ctx.error("defender", f"exit {p.returncode}: {(p.stdout or p.stderr).strip()[-200:]}")
            return
        hits.extend(found)
    _report(ctx, "Defender", hits)
    ctx.checks["defender"] = "ok"


def scan_mdatp(ctx: EntryContext, folders: list[Path] | None = None) -> None:
    exe = ctx.tool("mdatp")
    if not exe:
        return
    hits: list[tuple[str, str]] = []
    for folder in folders or _folders(ctx):
        try:
            p = run_tool([exe, "scan", "custom", "--path", str(folder)], timeout=1800)
        except ToolError as exc:
            ctx.error("mdatp", str(exc))
            return
        hits.extend(parse_mdatp(p.stdout + "\n" + p.stderr))
    _report(ctx, "Defender for Mac", hits)
    ctx.checks["mdatp"] = "ok"


def scan_clamav_batch(cfg, exe: str, folders_by_slug: dict[str, list[Path]], timeout: int) -> tuple[dict, str]:
    """One clamscan run over every entry's folders (loading the signatures once).

    Returns ({slug: [(path, threat), ...]}, error). clamscan reloads ~3.6M signatures on every start,
    so scanning per entry would add tens of seconds per entry.
    """
    import tempfile

    all_folders = [(slug, f) for slug, fs in folders_by_slug.items() for f in fs if f.exists()]
    hits: dict[str, list[tuple[str, str]]] = {slug: [] for slug in folders_by_slug}
    if not all_folders:
        return hits, ""
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as fh:
        fh.write("\n".join(str(f) for _, f in all_folders))
        listfile = fh.name
    try:
        p = run_tool([exe, "-r", "-i", "--no-summary", "--stdout", "--max-filesize=2000M", "--max-scansize=4000M",
                      f"--file-list={listfile}"], timeout=timeout)
    except ToolError as exc:
        return hits, str(exc)
    finally:
        Path(listfile).unlink(missing_ok=True)
    found = parse_clamscan(p.stdout)
    if p.returncode not in (0, 1) and not found:
        return hits, f"exit {p.returncode}: {(p.stderr or p.stdout).strip()[-200:]}"
    resolved = [(slug, f.resolve()) for slug, f in all_folders]
    for path, name in found:
        rp = Path(path).resolve()
        slug = next((s for s, f in resolved if rp == f or f in rp.parents), None)
        if slug is not None:
            hits[slug].append((path, name))
    return hits, ""


def apply_clamav_hits(ctx: EntryContext, hits: list[tuple[str, str]], error: str = "") -> None:
    if error:
        ctx.error("clamav", error)
        return
    _report(ctx, "ClamAV", hits)
    ctx.checks["clamav"] = "ok"


def entry_folders(ctx: EntryContext) -> list[Path]:
    return _folders(ctx)


def run(ctx: EntryContext, folders: list[Path] | None = None, defer_clamav: bool = False) -> None:
    """Scan with the platform's antivirus. With defer_clamav, ClamAV is left for one batched scan later."""
    if not ctx.cfg.section("antivirus").get("enabled", True):
        ctx.not_run("antivirus", "disabled in config.toml")
        return
    plat = ctx.cfg.platform
    if defer_clamav and ctx.tool("clamav") and (ctx.cfg.check_enabled("clamav") or ctx.cfg.check_enabled("antivirus")):
        ctx.checks["clamav"] = "deferred (batch scan)"
        ctx.info["_clamav_deferred"] = True
    if plat == "windows":
        if ctx.cfg.check_enabled("defender") or ctx.cfg.check_enabled("antivirus"):
            scan_defender(ctx, folders)
        if ctx.tool("clamav") and ctx.cfg.check_enabled("clamav") and not ctx.info.get("_clamav_deferred"):
            scan_clamav(ctx, folders)
    else:
        if (ctx.cfg.check_enabled("clamav") or ctx.cfg.check_enabled("antivirus")) and not ctx.info.get("_clamav_deferred"):
            scan_clamav(ctx, folders)
        if plat == "macos" and (ctx.cfg.check_enabled("mdatp") or ctx.cfg.check_enabled("antivirus")):
            scan_mdatp(ctx, folders)
