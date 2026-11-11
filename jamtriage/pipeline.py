"""The eight-step pipeline: collect (separate command), inventory, unpack, hash, lookups, local checks,
score and report (separate command). Every entry's local results are saved, so reruns skip finished work."""
from __future__ import annotations

import hashlib
import json
import shutil
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

from rich.console import Console

from .checks import EntryContext, antivirus, capa, code, diec, engine, pe, strings, unwrap, web, yara_scan
from .checks.inventory import file_flags, hash_all, inventory, unpack
from .config import Config
from .entries import Entry, discover_entries
from .filetypes import is_lookup_worthy
from .lookups import LookupManager, enabled_services, make_limiter, quota_warnings
from .models import FileRecord, Finding, Severity
from .scoring import apply_reputation, counts, dedupe, independent_sources, lookup_findings, verdict
from .state import LookupCache, State, iso_now
from .tools import ToolStatus, print_tool_table, probe_tools, tool_version

PIPELINE_VERSION = 4
# Finding source -> tool key. When a full re-analysis runs on a machine without that tool (e.g. back on the
# Mac after `--only defender` in a Windows VM), the previous findings of that source are carried over.
SOURCE_TOOL = {"defender": "defender", "clamav": "clamav", "defenderformac": "mdatp", "mdatp": "mdatp",
               "capa": "capa", "diec": "diec", "yara": "yara"}
# --only names -> finding sources they own (so a partial rerun replaces just those findings)
ONLY_SOURCES = {
    "defender": {"defender"}, "clamav": {"clamav"}, "mdatp": {"defenderformac", "mdatp"},
    "antivirus": {"defender", "clamav", "defenderformac", "mdatp"}, "yara": {"yara"}, "capa": {"capa"},
    "diec": {"diec"}, "pe": {"pe"}, "strings": {"strings"}, "code": {"code"}, "web": {"web"},
    "unwrap": {"unwrap"}, "lookups": set(),
}


def layout(entry: Entry) -> str:
    """Which build files exist and how big they are (platform-independent; no timestamps)."""
    h = hashlib.sha256()
    for p in entry.build_files():
        h.update(f"{p.relative_to(entry.root).as_posix()}|{p.stat().st_size}\n".encode())
    return h.hexdigest()


def fingerprint(entry: Entry, cfg: Config, tools: dict | None = None) -> str:
    """Everything that should trigger a re-analysis: build files, rules, relevant config, platform, tools."""
    h = hashlib.sha256()
    h.update(f"v{PIPELINE_VERSION}|{cfg.platform}\n".encode())
    for p in entry.build_files():
        st = p.stat()
        h.update(f"{p.relative_to(entry.root).as_posix()}|{st.st_size}|{int(st.st_mtime)}\n".encode())
    for rf in sorted(cfg.rules_dir.rglob("*")) if cfg.rules_dir.is_dir() else []:
        if rf.is_file():
            h.update(f"{rf.relative_to(cfg.rules_dir).as_posix()}|{rf.stat().st_size}|{int(rf.stat().st_mtime)}\n".encode())
    for sec in ("unpack", "antivirus", "tools"):
        h.update(json.dumps(cfg.raw.get(sec, {}), sort_keys=True, default=str).encode())
    h.update(str(cfg.section("virustotal").get("max_lookups_per_entry")).encode())
    if tools:
        h.update(",".join(sorted(k for k, t in tools.items() if t.status == "available")).encode())
    return h.hexdigest()


def local_path(cfg: Config, slug: str) -> Path:
    return cfg.results_dir / slug / "local.json"


def result_path(cfg: Config, slug: str) -> Path:
    return cfg.results_dir / f"{slug}.json"


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1, default=str), encoding="utf-8")
    tmp.replace(path)


def _ctx_to_dict(ctx: EntryContext, entry: Entry, fp: str) -> dict:
    return {
        "slug": ctx.slug, "fingerprint": fp, "layout": ctx.info.get("_layout", ""), "completed": iso_now(),
        "platform": ctx.cfg.platform,
        "entry": {"title": entry.title, "author": entry.author, "url": entry.url, "platforms": entry.platforms,
                  "claimed_engine": entry.claimed_engine, "root": str(entry.root)},
        "files": [r.to_dict() for r in ctx.files],
        "findings": [f.to_dict() for f in ctx.findings],
        "checks": ctx.checks,
        "info": {k: v for k, v in ctx.info.items() if not k.startswith("_")},
    }


def _ctx_from_dict(cfg: Config, entry: Entry, tools, data: dict) -> EntryContext:
    ctx = EntryContext(cfg, entry.slug, entry.root, tools)
    ctx.files = [FileRecord.from_dict(d) for d in data.get("files", [])]
    ctx.findings = [Finding.from_dict(d) for d in data.get("findings", [])]
    ctx.checks = dict(data.get("checks", {}))
    ctx.info = dict(data.get("info", {}))
    return ctx


class Pipeline:
    def __init__(self, cfg: Config, console: Console | None = None, lookup_clients: dict | None = None,
                 services: list[str] | None = None):
        self.cfg = cfg
        self.console = console or Console()
        cfg.ensure_dirs()
        self.state = State(cfg.state_db)
        self.cache = LookupCache(cfg.cache_file)
        self.tools: dict[str, ToolStatus] = probe_tools(cfg.platform, cfg.tool_paths())
        from .checks import set_tool_memory_limit
        set_tool_memory_limit(cfg.section("tools").get("max_tool_memory_mb", 8192))
        if self.tools.get("7z") and self.tools["7z"].status == "available":
            from . import unpack as _unpack
            _unpack.SEVEN_ZIP_OVERRIDE = self.tools["7z"].path
        self.services = services if services is not None else enabled_services(cfg)
        self.lookup_clients = lookup_clients
        self.defer_clamav = True   # analyze() batches ClamAV into one scan per run
        self._active: dict[str, str] = {}
        self._active_lock = threading.Lock()

    # ------------------------------------------------------------------ helpers
    def log(self, msg: str, entry: str = "") -> None:
        self.state.log(msg, entry)

    def _set_active(self, slug: str, stage: str | None) -> None:
        """Record what each worker is doing (stage None = entry finished) for the dashboard's "now" line."""
        with self._active_lock:
            if stage is None:
                self._active.pop(slug, None)
            else:
                self._active[slug] = stage
            active = dict(self._active)
        if len(active) == 1:
            (entry, stage_), = active.items()
            cur = {"entry": entry, "stage": stage_}
        else:
            cur = {"entry": f"{len(active)} entries" if active else "",
                   "stage": " · ".join(f"{e}: {s}" for e, s in active.items())}
        self.state.set_meta("current", {**cur, "active": [{"entry": e, "stage": s} for e, s in active.items()]})

    def _stage(self, ctx: EntryContext, name: str, fn: Callable, *args) -> None:
        self.state.upsert_entry(ctx.slug, stage=name, status="in_progress")
        self._set_active(ctx.slug, name)
        try:
            fn(*args)
        except Exception as exc:  # noqa: BLE001  one broken file must not stop the run
            ctx.error(name, f"{type(exc).__name__}: {exc}")
            self.log(f"{name} failed: {exc}", ctx.slug)
            if self.cfg.raw.get("debug"):
                traceback.print_exc()

    def record_versions(self) -> None:
        versions = {}
        for key, st in self.tools.items():
            v = ""
            if st.status == "available":
                args = {"clamav": ("--version",), "diec": ("--version",), "capa": ("--version",),
                        "7z": ("i",), "defender": ("-h",), "gdre": ("--version",), "ilspycmd": ("--version",)}.get(key, ("--version",))
                v = tool_version(st.path, args) if key not in ("defender",) else ""
            versions[key] = {"status": st.status, "path": st.path, "version": v}
        yara_dir = self.cfg.rules_dir / "yara"
        rulesets = []
        for f in sorted([*yara_dir.rglob("*.yar"), *yara_dir.rglob("*.yara")]) if yara_dir.is_dir() else []:
            rulesets.append({"file": f.name, "sha256": hashlib.sha256(f.read_bytes()).hexdigest()[:16],
                             "modified": time.strftime("%Y-%m-%d", time.gmtime(f.stat().st_mtime))})
        if self.cfg.platform == "windows" and self.tools.get("defender") and self.tools["defender"].status == "available":
            try:
                import subprocess
                p = subprocess.run(["powershell", "-NoProfile", "-Command",
                                    "(Get-MpComputerStatus).AntivirusSignatureVersion"],
                                   capture_output=True, text=True, timeout=60)
                versions["defender"]["version"] = "signatures " + p.stdout.strip()
            except Exception:  # noqa: BLE001
                pass
        self.state.set_meta("versions", {"tools": versions, "yara": rulesets, "platform": self.cfg.platform})

    # ------------------------------------------------------------------ local analysis
    def run_local(self, entry: Entry, prev: dict | None = None) -> EntryContext:
        cfg = self.cfg
        only = set(cfg.only)
        if prev and only and self._partial_ok(entry, prev):
            # Partial rerun (e.g. --only defender inside a Windows VM): replace just those checks' findings.
            ctx = _ctx_from_dict(cfg, entry, self.tools, prev)
            owned = set().union(*(ONLY_SOURCES.get(o, {o}) for o in only))
            ctx.findings = [f for f in ctx.findings if f.source not in owned]
            for name in only:
                ctx.checks.pop(name, None)
            self._run_checks(ctx, partial=True)
            return ctx

        if only:
            self.console.print(f"[yellow]{entry.slug}: no matching saved results for a partial run "
                               f"(build changed or unpacked files missing); running the full analysis instead.[/]")
        ctx = EntryContext(cfg, entry.slug, entry.root, self.tools)
        ctx.info["claimed_engine"] = entry.claimed_engine
        saved_only, cfg.only = cfg.only, set()   # a full analysis always runs every check
        try:
            self._stage(ctx, "inventory", inventory, ctx, entry)
            self._stage(ctx, "unpack", unpack, ctx)
            self._stage(ctx, "hash", hash_all, ctx)
            self._stage(ctx, "flags", file_flags, ctx)
            self._stage(ctx, "engine", engine.detect, ctx)
            self._run_checks(ctx, partial=False)
        finally:
            cfg.only = saved_only
        if prev and prev.get("layout") == layout(entry):
            self._carry_over(ctx, prev)
        return ctx

    def _partial_ok(self, entry: Entry, prev: dict) -> bool:
        """A partial (--only) rerun is safe if the build files are the same and the unpacked files exist."""
        if prev.get("layout") != layout(entry):
            return False
        for d in prev.get("files", []):
            if d.get("origin") in ("unpacked", "unwrapped"):
                ctx = EntryContext(self.cfg, entry.slug, entry.root, self.tools)
                if not ctx.abspath(d["path"]).exists():
                    return False
        return True

    def _carry_over(self, ctx: EntryContext, prev: dict) -> None:
        """Keep findings no local check on this machine can reproduce: sandbox detonation results, and
        checks whose tool isn't available here (e.g. Defender results from a Windows VM)."""
        keep = []
        # Sandbox results belong to one exact file: keep them only if the main exe is byte-for-byte the same.
        def main_sha(files, main):
            return next((f.get("sha256") if isinstance(f, dict) else f.sha256 for f in files
                         if (f.get("path") if isinstance(f, dict) else f.path) == main), None)
        same_exe = bool(main_sha(prev.get("files", []), prev.get("info", {}).get("main_exe"))) and \
            main_sha(prev.get("files", []), prev.get("info", {}).get("main_exe")) == \
            main_sha(ctx.files, ctx.info.get("main_exe"))
        for d in prev.get("findings", []):
            src_tool = SOURCE_TOOL.get(d.get("source", ""))
            if (d.get("rule", "").startswith("detonation.") and same_exe) or (src_tool and not ctx.tool(src_tool)):
                keep.append(Finding.from_dict(d))
        for name, status in (prev.get("checks") or {}).items():
            tool = SOURCE_TOOL.get(name)
            if tool and not ctx.tool(tool) and status == "ok":
                ctx.checks[name] = "ok (carried over from an earlier run)"
        for key in ("detonation", "sandbox"):
            if prev.get("info", {}).get(key) and same_exe:
                ctx.info[key] = prev["info"][key]
        for engine_name, res in (prev.get("info", {}).get("av") or {}).items():
            tool = {"Defender": "defender", "ClamAV": "clamav", "Defender for Mac": "mdatp"}.get(engine_name)
            if tool and not ctx.tool(tool):
                ctx.info.setdefault("av", {})[engine_name] = res
        ctx.findings = dedupe(ctx.findings + keep)

    def _run_checks(self, ctx: EntryContext, partial: bool) -> None:
        self._stage(ctx, "pe", pe.run, ctx)        # first: decides which runtime files are verifiably genuine
        self._stage(ctx, "diec", diec.run, ctx)
        if not partial:
            self._stage(ctx, "unwrap", unwrap.run, ctx)
            new_paths = set(ctx.info.get("_unwrapped_new", []))
            new = [r for r in ctx.files if r.path in new_paths]
            if new:
                self._stage(ctx, "hash", hash_all, ctx, new)
                self._stage(ctx, "pe", pe.run, ctx, [r for r in new if r.kind == "pe"])
        self._stage(ctx, "strings", strings.run, ctx)
        self._stage(ctx, "yara", yara_scan.run, ctx)
        self._stage(ctx, "antivirus", antivirus.run, ctx, None, self.defer_clamav)
        self._stage(ctx, "capa", capa.run, ctx)
        self._stage(ctx, "code", code.run, ctx)
        self._stage(ctx, "web", web.run, ctx)
        # Files that disappeared while we worked were most likely quarantined by real-time antivirus.
        # (Only meaningful when we just unpacked them ourselves, i.e. on a full run.)
        for rec in ([] if partial else ctx.files):
            if "vanished" not in rec.tags and not ctx.abspath(rec).exists():
                rec.tags.append("vanished")
                ctx.add(Finding(rule="av.vanished", severity=Severity.HIGH,
                                title="File vanished during analysis (likely quarantined by antivirus)",
                                file=rec.path, source="antivirus"))
        ctx.findings = dedupe(ctx.findings)

    # ------------------------------------------------------------------ lookups
    def lookup_plan(self, ctx: EntryContext) -> dict[str, list[tuple[str, int]]]:
        """Return {service: [(sha256, tier), ...]} for one entry."""
        web_roots = [r + "/" for r in ctx.info.get("web_roots", [])]
        main = ctx.info.get("main_exe", "")

        def worthy(r: FileRecord) -> bool:
            if not r.sha256 or not is_lookup_worthy(r.kind, r.tags):
                return False
            if r.kind not in ("pe", "elf", "macho") and (any(r.path.startswith(w) for w in web_roots)
                                                          or r.origin == "unwrapped"
                                                          or "/node_modules/" in r.path.lower()):
                return False
            return True

        cands = [r for r in ctx.files if worthy(r)]
        tier1 = [r for r in cands if r.kind != "archive" and "trusted-runtime" not in r.tags]
        tier1.sort(key=lambda r: (r.path != main, r.origin == "unwrapped", r.kind not in ("pe", "elf", "macho"), -r.size))
        tier2 = [r for r in ctx.files if r.origin == "builds" and r.kind == "archive" and r.sha256]
        tier3 = [r for r in cands if r.kind != "archive" and "trusted-runtime" in r.tags]

        def uniq(items: list[tuple[str, int]]) -> list[tuple[str, int]]:
            seen, out = set(), []
            for sha, t in items:
                if sha not in seen:
                    seen.add(sha)
                    out.append((sha, t))
            return out

        t1 = uniq([(r.sha256, 1) for r in tier1])
        rest = [(r.sha256, 2) for r in tier2] + [(r.sha256, 3) for r in tier3]
        plan = {}
        for svc in self.services:
            # Cap per entry for every service: the most important files (main exe first) come first,
            # then archives and verified runtime files. Protects quotas from apps with hundreds of DLLs.
            cap = int(self.cfg.section(svc).get("max_lookups_per_entry") or 12)
            plan[svc] = uniq(t1[:cap] + rest)[:cap + 10]
        return plan

    def enqueue(self, ctx: EntryContext) -> dict[str, list[str]]:
        plan = self.lookup_plan(ctx)
        allow = self.cfg.lookup_allowlist
        out: dict[str, list[str]] = {}
        for svc, items in plan.items():
            out[svc] = []
            for sha, tier in items:
                if allow is not None and sha not in allow:
                    continue
                out[svc].append(sha)
                if self.cache.get(sha, svc) is None:
                    self.state.enqueue_lookup(svc, sha, tier, ctx.slug)
        return out

    # ------------------------------------------------------------------ scoring
    def score(self, slug: str, local: dict, provisional: bool = False) -> dict:
        ctx_findings = [Finding.from_dict(d) for d in local.get("findings", [])]
        files = [FileRecord.from_dict(d) for d in local.get("files", [])]
        lookups = local.get("lookups", {})
        pending = {svc: {sha for sha in hashes if self.state.lookup_status(svc, sha) == "pending"}
                   for svc, hashes in lookups.items()}
        lf, summary = lookup_findings(files, self.cache.all_for, pending, local.get("info", {}).get("engines", []),
                                      local.get("info", {}).get("signatures", {}))
        findings = dedupe(apply_reputation(ctx_findings + lf, files, self.cache.all_for))
        findings.sort(key=lambda f: (-int(f.severity), f.rule, f.file))
        has_web = bool(local.get("info", {}).get("web_roots"))
        v, reasons = verdict(findings, has_web)
        deferred = any(str(s).startswith("deferred") for s in (local.get("checks") or {}).values())
        provisional = provisional or deferred or any(pending.values())
        top = findings[0] if findings else None
        result = {
            **{k: local[k] for k in ("slug", "entry", "checks", "platform") if k in local},
            "info": local.get("info", {}),
            "files": local.get("files", []),
            "findings": [f.to_dict() for f in findings],
            "verdict": v,
            "reasons": [f.to_dict() for f in reasons],
            "lookups": summary,
            "pending": {k: sorted(v_) for k, v_ in pending.items() if v_},
            "lookup_services": sorted(k for k, v_ in lookups.items() if v_),
            "lookup_errors": {svc: n for svc in lookups
                              if (n := sum(1 for sha in lookups[svc] if self.state.lookup_status(svc, sha) == "error"))},
            "counts": counts(findings),
            "sources": independent_sources(findings),
            "has_web": has_web,
            "provisional": provisional,
            "scored": iso_now(),
        }
        _write_json(result_path(self.cfg, slug), result)
        self.state.upsert_entry(slug, status="provisional" if provisional else "done", stage="", verdict=v,
                                counts=result["counts"],
                                top_severity=top.severity.label if top and top.severity >= Severity.LOW else "",
                                top_finding=top.title if top and top.severity >= Severity.LOW else "")
        return result

    # ------------------------------------------------------------------ main entry point
    def analyze(self, entries: list[Entry] | None = None, force: bool = False, show_tools: bool = True,
                wait_for_lookups: bool = True, sandbox: bool = False, workers: int | None = None) -> list[dict]:
        cfg = self.cfg
        acfg = cfg.section("analysis")
        workers = max(1, int(workers or acfg.get("workers", 3) or 1))
        capa.set_parallel_capa(int(acfg.get("max_parallel_capa", 2) or 1))
        if show_tools:
            print_tool_table(self.tools, cfg.platform, self.console)
        for w in quota_warnings(cfg):
            self.console.print(f"[yellow]{w}[/]")
            self.state.log(w)
        self.record_versions()
        entries = entries if entries is not None else discover_entries(cfg.builds_dir)
        if not entries:
            self.console.print(f"[yellow]No entries found in {cfg.builds_dir}. Run `triage collect <jam-url>` first.[/]")
        run_meta = {"state": "running", "started": iso_now(), "started_ts": time.time(), "total": len(entries),
                    "slugs": [e.slug for e in entries], "analysed": 0, "reused": 0, "services": self.services,
                    "steps": [{"key": k, "title": t, "state": "pending", "detail": ""} for k, t in RUN_STEPS]}
        if not sandbox:
            self._step(run_meta, "sandbox", "skipped", "not requested (add --sandbox)")
        if not (self.tools.get("clamav") and self.tools["clamav"].status == "available"):
            self._step(run_meta, "clamav", "skipped", "ClamAV not installed")
        elif cfg.only and not cfg.only & {"clamav", "antivirus"}:
            self._step(run_meta, "clamav", "skipped", "not part of --only")
        if not self.services:
            self._step(run_meta, "lookups", "skipped", "no lookup service enabled")
        elif cfg.only and "lookups" not in cfg.only:
            self._step(run_meta, "lookups", "skipped", "not part of --only (cached results are reused)")
        self._step(run_meta, "static", "running")
        for e in entries:
            self.state.upsert_entry(e.slug, title=e.title, status="queued", verdict="")

        manager = LookupManager(cfg, self.cache, self.services, self.lookup_clients)
        manager.start()
        locals_: dict[str, dict] = {}
        final_state = "done"
        try:
            run_meta["workers"] = min(workers, max(1, len(entries)))
            # Entries run in a pool of workers; results are handled here, in the main thread, as they finish.
            with ThreadPoolExecutor(max_workers=run_meta["workers"], thread_name_prefix="entry") as pool:
                futures = {pool.submit(self._analyze_entry_safe, entry, i, len(entries), force): entry
                           for i, entry in enumerate(entries, 1)}
                try:
                    for fut in as_completed(futures):
                        entry = futures[fut]
                        local, reused = fut.result()
                        locals_[entry.slug] = local
                        run_meta["reused" if reused else "analysed"] += 1
                        self.state.set_meta("run", run_meta)
                        self.score(entry.slug, local, provisional=True)   # while ClamAV batch / lookups continue
                except BaseException:
                    for f in futures:      # Ctrl+C: don't start queued entries; running tools are killed by run_tool
                        f.cancel()
                    raise
            locals_ = {e.slug: locals_[e.slug] for e in entries if e.slug in locals_}   # keep the entry order
            self._step(run_meta, "static", "done", f"{len(entries)} entr{'y' if len(entries) == 1 else 'ies'}")
            if self._step_state(run_meta, "clamav") != "skipped":
                self._step(run_meta, "clamav", "running")
                try:
                    self._batch_clamav(entries, locals_)
                    self._step(run_meta, "clamav", "done")
                except Exception as exc:  # noqa: BLE001
                    self.console.print(f"[red]ClamAV batch scan failed: {exc}[/]")
                    self.log(f"ClamAV batch scan failed: {exc}")
                    self._step(run_meta, "clamav", "failed", str(exc)[:200])
            manager.producer_finished()
            if wait_for_lookups and manager.workers:
                self._step(run_meta, "lookups", "running")
                left = self._wait_lookups(manager)
                self._step(run_meta, "lookups", "done", f"{left} still pending (budget or errors); "
                           "`triage recheck` picks them up later" if left else "")
            elif self._step_state(run_meta, "lookups") != "skipped":
                self._step(run_meta, "lookups", "skipped", "--no-wait: lookups continue in later runs")
        except KeyboardInterrupt:
            final_state = "interrupted"
            raise
        except Exception:
            final_state = "failed"
            raise
        finally:
            if final_state != "done" or not wait_for_lookups:
                manager.stop()
            if final_state != "done":
                self.state.set_meta("run", {**run_meta, "state": final_state, "finished": iso_now()})
        self._step(run_meta, "score", "running")
        results = [self.score(slug, local) for slug, local in locals_.items()]
        self._step(run_meta, "score", "done")
        if sandbox:   # opt-in per run: `triage analyze --sandbox`
            if not wait_for_lookups or cfg.only:
                self.console.print("[yellow]--sandbox is skipped with --no-wait or --only.[/]")
                self._step(run_meta, "sandbox", "skipped", "not with --no-wait or --only")
            else:
                self._step(run_meta, "sandbox", "running")
                results = self._sandbox_step(list(locals_), results)
                self._step(run_meta, "sandbox", "done", "submitted / collected what was ready; "
                           "`triage sandbox collect` later fetches the rest")
        self.state.set_meta("run", {**run_meta, "state": "done", "finished": iso_now()})
        self.state.set_meta("current", {"entry": "", "stage": ""})
        return results

    def _sandbox_step(self, slugs: list[str], results: list[dict]) -> list[dict]:
        """Opt-in (`--sandbox`): submit new entries to the VirusTotal and Hybrid Analysis sandboxes and collect
        the results that are ready. Runs after the hash lookups, so files VirusTotal already has aren't uploaded."""
        from .sandbox import virustotal as vtsandbox
        if not vtsandbox.allowed(self.cfg):
            return results
        providers = vtsandbox.available(self.cfg)
        if not providers:
            self.console.print("[yellow]--sandbox: no sandbox available (needs VT_API_KEY and/or HA_API_KEY).[/]")
            return results
        names = {"virustotal": "VirusTotal", "hybrid": "Hybrid Analysis"}
        for prov in providers:
            self.state.set_meta("current", {"entry": "", "stage": f"{names[prov]} sandbox"})
            self.console.print(f"[bold]{names[prov]} sandbox[/] (opt-in): submitting new entries, "
                               f"collecting ready results…")
            try:
                vtsandbox.run(self.cfg, self.console, "upload", [prov], slugs)
                vtsandbox.run(self.cfg, self.console, "collect", [prov], slugs, pipe=self)
            except Exception as exc:  # noqa: BLE001  never lose the static results over an optional step
                self.console.print(f"[red]{names[prov]} sandbox step failed: {exc}[/]")
                self.log(f"{names[prov]} sandbox step failed: {exc}")
        out = []
        for r in results:
            p = result_path(self.cfg, r["slug"])
            try:
                out.append(json.loads(p.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                out.append(r)
        return out

    def _analyze_entry_safe(self, entry: Entry, i: int, n: int, force: bool) -> tuple[dict, bool]:
        try:
            return self._analyze_entry(entry, i, n, force)
        except Exception as exc:  # noqa: BLE001  one broken entry must not stop the run
            self.console.print(f"[red]{entry.slug}: could not analyse: {exc}[/]")
            self.log(f"could not analyse: {exc}", entry.slug)
            return self._failed_entry(entry, exc), False
        finally:
            self._set_active(entry.slug, None)

    def _analyze_entry(self, entry: Entry, i: int, n: int, force: bool) -> tuple[dict, bool]:
        cfg = self.cfg
        lp = local_path(cfg, entry.slug)
        fp = fingerprint(entry, cfg, self.tools)
        prev = None
        if lp.is_file():
            try:
                prev = json.loads(lp.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                prev = None
        if prev and prev.get("fingerprint") == fp and not force and not cfg.only:
            self.console.print(f"[dim][{i}/{n}] {entry.slug}: unchanged, reusing saved results[/]")
            self.state.upsert_entry(entry.slug, status="reused")
            prev["lookups"] = self.enqueue(_ctx_from_dict(cfg, entry, self.tools, prev))
            _write_json(lp, prev)
            return prev, True
        self.console.print(f"[{i}/{n}] [bold]{entry.slug}[/]: analysing…")
        self.log("analysing", entry.slug)
        partial = bool(prev and cfg.only and self._partial_ok(entry, prev))
        ctx = self.run_local(entry, prev)
        ctx.info["_layout"] = layout(entry)
        # A partial rerun keeps the earlier fingerprint: the other checks' results are still the old ones.
        local = _ctx_to_dict(ctx, entry, prev["fingerprint"] if partial else fp)
        if partial and "lookups" not in cfg.only:
            local["lookups"] = prev.get("lookups", {})
        else:
            local["lookups"] = self.enqueue(ctx)
        self.log(f"local checks done: {ctx.info.get('engine', 'unknown')}, {len(ctx.findings)} finding(s)", entry.slug)
        _write_json(lp, local)
        return local, False

    def _failed_entry(self, entry: Entry, exc: Exception) -> dict:
        return {"slug": entry.slug, "fingerprint": "", "layout": "", "platform": self.cfg.platform,
                "entry": {"title": entry.title, "author": entry.author, "url": entry.url, "platforms": entry.platforms,
                          "claimed_engine": entry.claimed_engine, "root": str(entry.root)},
                "files": [], "checks": {"analysis": f"error ({exc})"}, "info": {}, "lookups": {},
                "findings": [Finding(rule="analysis.error", severity=Severity.HIGH,
                                     title="Entry could not be analysed at all", detail=str(exc)[:300],
                                     source="pipeline").to_dict()]}

    def _batch_clamav(self, entries: list[Entry], locals_: dict[str, dict]) -> None:
        """Run the deferred ClamAV scans of this run's entries as a single clamscan invocation."""
        todo = {e.slug: e for e in entries
                if e.slug in locals_ and str(locals_[e.slug].get("checks", {}).get("clamav", "")).startswith("deferred")}
        if not todo:
            return
        if not self.tools.get("clamav") or self.tools["clamav"].status != "available":
            return
        ctxs = {slug: _ctx_from_dict(self.cfg, e, self.tools, locals_[slug]) for slug, e in todo.items()}
        first = next(iter(ctxs.values()))
        first.info["av_update"] = antivirus.update_signatures(first, "clamav")
        self.state.set_meta("current", {"entry": f"{len(ctxs)} entries", "stage": "ClamAV batch scan"})
        self.console.print(f"ClamAV: scanning {len(ctxs)} entr{'y' if len(ctxs) == 1 else 'ies'} in one pass…")
        timeout = int(self.cfg.section("antivirus").get("timeout_seconds", 1800)) * max(1, len(ctxs) // 10 + 1)
        hits, error = antivirus.scan_clamav_batch(
            self.cfg, self.tools["clamav"].path, {s: antivirus.entry_folders(c) for s, c in ctxs.items()}, timeout)
        for slug, ctx in ctxs.items():
            ctx.info["av_update"] = first.info["av_update"]
            antivirus.apply_clamav_hits(ctx, hits.get(slug, []), error)
            local = locals_[slug]
            local["findings"] = [f.to_dict() for f in dedupe(ctx.findings)]
            local["checks"], local["info"] = ctx.checks, {k: v for k, v in ctx.info.items() if not k.startswith("_")}
            _write_json(local_path(self.cfg, slug), local)
            n = len(hits.get(slug, []))
            if n:
                self.log(f"ClamAV: {n} detection(s)", slug)
        self.log(f"ClamAV batch scan done ({len(ctxs)} entries)" + (f": {error}" if error else ""))

    def _step(self, run_meta: dict, key: str, state: str, detail: str = "") -> None:
        """Update one of the run's steps (shown on the dashboard) and save it."""
        for st in run_meta.get("steps", []):
            if st["key"] == key:
                if st["state"] == "skipped" and state in ("running", "done"):
                    return                       # e.g. lookups outside --only: the decision stands
                st["state"], st["detail"] = state, detail
                st["at" if state == "running" else "ended"] = time.time()
        self.state.set_meta("run", run_meta)

    @staticmethod
    def _step_state(run_meta: dict, key: str) -> str:
        return next((st["state"] for st in run_meta.get("steps", []) if st["key"] == key), "")

    def _wait_lookups(self, manager: LookupManager) -> int:
        self.state.set_meta("current", {"entry": "", "stage": "hash lookups"})
        while any(w.is_alive() for w in manager.workers.values()):
            pend = {s: self.state.pending_count(s) for s in manager.workers}
            self.console.print(f"[dim]waiting for hash lookups: {pend}[/]", end="\r")
            for w in manager.workers.values():
                w.join(timeout=2)
        self.console.print()
        for s, w in manager.workers.items():
            if w.stopped_reason and w.stopped_reason != "queue empty":
                self.console.print(f"[yellow]{s}: {w.stopped_reason}; {self.state.pending_count(s)} lookup(s) pending[/]")
        return sum(self.state.pending_count(s) for s in manager.workers)


RUN_STEPS = [
    ("static", "Static checks per entry (unpack, rules, YARA, capa, PE)"),
    ("clamav", "ClamAV scan (all entries in one pass)"),
    ("lookups", "Hash lookups (VirusTotal, MalwareBazaar, MetaDefender)"),
    ("score", "Final scoring"),
    ("sandbox", "Sandboxes: VirusTotal + Hybrid Analysis (opt-in)"),
]


def quota_status(cfg: Config, state: State) -> dict:
    out = {}
    for svc in ("virustotal", "malwarebazaar", "metadefender"):
        sec = cfg.section(svc)
        lim = make_limiter(cfg, state, svc)
        out_month = state.quota_used_month(svc)
        out[svc] = {
            "used_month": out_month,
            "monthly_budget": lim.monthly,
            "requests_per_minute": round(60 / lim.interval, 2),
            "enabled": bool(sec.get("enabled")) and bool(cfg.key({"virustotal": "VT_API_KEY",
                                                                   "malwarebazaar": "MB_AUTH_KEY",
                                                                   "metadefender": "MD_API_KEY"}[svc])),
            "used_today": state.quota_used(svc),
            "budget": lim.budget,
            "next_request_in": round(lim.next_request_in()),
            "pending": state.pending_count(svc),
            "paused": lim.paused(),
        }
    # Hybrid Analysis sandbox submissions (only used with --sandbox / `triage sandbox` / `detonate`).
    from .lookups import hybrid_limiters
    _, subs = hybrid_limiters(cfg, state)
    out["hybrid-analysis"] = {
        "enabled": bool(cfg.key("HA_API_KEY")),
        "used_today": state.quota_used("hybrid-submit"),
        "budget": subs.budget,
        "next_request_in": round(subs.next_request_in()),
        "pending": sum(1 for r in state.sandbox_all("hybrid") if r["status"] in ("submitted", "waiting")),
        "paused": subs.paused(),
    }
    return out


def clean_entry_dirs(cfg: Config, slug: str) -> None:
    for d in (cfg.unpacked_dir / slug, cfg.unwrapped_dir / slug):
        shutil.rmtree(d, ignore_errors=True)
