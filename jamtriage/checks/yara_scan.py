"""YARA (yara-python) with the rules in rules/yara/ (YARA Forge core recommended)."""
from __future__ import annotations

import threading
from pathlib import Path

from ..models import Finding, Severity
from . import EntryContext

_EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}
_lock = threading.Lock()
_compiled: dict[str, object] = {}


def compile_rules(rules_dir: Path):
    """Compile every .yar/.yara file under rules/yara once. Files that fail to compile are skipped."""
    import yara

    key = str(rules_dir)
    with _lock:
        if key in _compiled:
            return _compiled[key]
        files = sorted([*rules_dir.rglob("*.yar"), *rules_dir.rglob("*.yara")]) if rules_dir.is_dir() else []
        good: dict[str, str] = {}
        errors: list[str] = []
        for i, f in enumerate(files):
            try:
                yara.compile(filepath=str(f), externals=_EXTERNALS)
                good[f"ns{i}_{f.stem}"[:60]] = str(f)
            except yara.Error as exc:
                errors.append(f"{f.name}: {exc}")
        compiled = (yara.compile(filepaths=good, externals=_EXTERNALS) if good else None, sorted(good.values()), errors)
        _compiled[key] = compiled
        return compiled


def run(ctx: EntryContext, records=None) -> None:
    if not ctx.cfg.check_enabled("yara"):
        return
    if not ctx.tool("yara"):
        ctx.not_run("yara", "yara-python not installed")
        return
    rules, files, errors = compile_rules(ctx.cfg.rules_dir / "yara")
    ctx.info["yara_rulesets"] = [Path(f).name for f in files]
    if errors:
        ctx.info["yara_errors"] = errors[:10]
    if rules is None:
        ctx.not_run("yara", "no rules in rules/yara (run `triage fetch-rules`)")
        return
    tools = ctx.cfg.section("tools")
    max_bytes = int(tools.get("max_scan_bytes", 256 << 20))
    timeout = int(tools.get("yara_timeout", 60))
    matches_out = ctx.info.setdefault("yara", {})
    for rec in records if records is not None else ctx.files:
        if "vanished" in rec.tags or rec.size > max_bytes or rec.size == 0:
            continue
        p = ctx.abspath(rec)
        ext = p.suffix.lower().lstrip(".")
        try:
            matches = rules.match(str(p), timeout=timeout,
                                  externals={"filename": p.name, "filepath": str(p), "extension": ext,
                                             "filetype": rec.kind, "owner": ""})
        except Exception as exc:  # noqa: BLE001  (yara.TimeoutError, yara.Error)
            ctx.add(Finding(rule="analysis.error", severity=Severity.LOW, title="YARA scan failed on file",
                            file=rec.path, detail=str(exc)[:200], source="yara"))
            continue
        if matches:
            names = [m.rule for m in matches]
            matches_out[rec.path] = names
            for m in matches:
                score = int(m.meta.get("score", 75)) if isinstance(m.meta, dict) and str(m.meta.get("score", "")).isdigit() else 75
                sev = Severity.HIGH if score >= 60 else Severity.MEDIUM if score >= 40 else Severity.LOW
                ctx.add(Finding(rule="yara.match", severity=sev, title=f"YARA rule match: {m.rule}", file=rec.path,
                                detail=str(m.meta.get("description", ""))[:200] if isinstance(m.meta, dict) else "",
                                source="yara"))
    ctx.checks["yara"] = "ok"
