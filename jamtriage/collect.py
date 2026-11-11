"""`triage collect`, `triage recheck` and `triage fetch-rules`."""
from __future__ import annotations

import csv
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import requests
from rich.console import Console
from rich.table import Table

from .config import Config
from .entries import discover_entries
from .hashing import sha256_file
from .unpack import Budget, Limits, unpack_zip

YARA_FORGE_CORE = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"


def collect(cfg: Config, jam_url: str, dest: Path | None = None, console: Console | None = None,
            extra_args: list[str] | None = None) -> int:
    console = console or Console()
    from .tools import which

    import importlib.util
    if importlib.util.find_spec("itch_dl"):
        # Through our wrapper: itch-dl 1.0.0 aborts on page fields it doesn't know (e.g. "Jams").
        base = [sys.executable, "-m", "jamtriage.itchdl_shim"]
    elif exe := which("itch-dl"):
        base = [exe]
    else:
        console.print("[red]itch-dl not found.[/] Install it with: pip install itch-dl")
        return 2
    key = cfg.key("ITCH_API_KEY")
    if not key:
        console.print("[red]ITCH_API_KEY is not set[/] (put it in .env; create one at itch.io/user/settings/api-keys)")
        return 2
    dest = dest or cfg.builds_dir
    dest.mkdir(parents=True, exist_ok=True)
    console.print(f"Downloading {jam_url} into {dest} with itch-dl…")
    cmd = [*base, "--api-key", key, "--download-to", str(dest), *(extra_args or []), jam_url]
    proc = subprocess.run(cmd)
    n = len(discover_entries(dest))
    console.print(f"itch-dl exited with {proc.returncode}; {n} entries in {dest}.")
    console.print("[dim]Paid or access-restricted entries aren't downloaded: put those by hand in "
                  f"{dest}/<entry>/ and they'll be analysed like the rest.[/]")
    return proc.returncode


def hash_builds(builds: Path) -> dict[tuple[str, str], str]:
    out = {}
    for e in discover_entries(builds):
        for p in e.build_files():
            out[(e.slug, "builds/" + p.relative_to(e.root).as_posix())] = sha256_file(p)
    return out


def _csv_unescape(s: str) -> str:
    """Undo report._csv_safe (a leading ' added before = + - @)."""
    return s[1:] if s.startswith("'") and s[1:2] in ("=", "+", "-", "@", "\t", "\r") else s


def compare_manifest(cfg: Config, fresh_builds: Path) -> list[dict]:
    manifest = cfg.out_dir / "manifest.csv"
    old: dict[tuple[str, str], str] = {}
    if manifest.is_file():
        with open(manifest, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                entry, file = (_csv_unescape(row.get(k) or "") for k in ("entry", "file"))
                if file.startswith("builds/"):
                    old[(entry, file)] = row.get("sha256") or ""
    new = hash_builds(fresh_builds)
    new_entries = {e for e, _ in new}
    changes = []
    for key in sorted(set(old) | set(new)):
        a, b = old.get(key), new.get(key)
        if a == b:
            continue
        status = "added" if a is None else "changed" if b is not None else \
            "removed" if key[0] in new_entries else "entry missing from the fresh download"
        changes.append({"entry": key[0], "file": key[1], "status": status, "old_sha256": a or "", "new_sha256": b or ""})
    return changes


def recheck(cfg: Config, fresh: Path | None, jam_url: str | None, console: Console | None = None,
            requery: bool = True) -> int:
    """Re-query cached hashes and compare the manifest with a fresh download."""
    from .lookups import LookupManager, enabled_services
    from .pipeline import Pipeline, local_path
    from .report import build_reports

    console = console or Console()
    if jam_url:
        fresh = cfg.data_dir / "builds-recheck"
        shutil.rmtree(fresh, ignore_errors=True)
        rc = collect(cfg, jam_url, fresh, console)
        if rc != 0:
            console.print("[bold yellow]itch-dl reported an error: the fresh download is incomplete. Entries it "
                          "didn't fetch show as 'entry missing from the fresh download', not as changes.[/]")
    fresh = fresh or cfg.builds_dir
    if not (cfg.out_dir / "manifest.csv").is_file():
        console.print("[yellow]No out/manifest.csv yet: run `triage report` first to have something to compare.[/]")
    else:
        changes = compare_manifest(cfg, fresh)
        out = cfg.out_dir / "recheck.csv"
        with open(out, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=["entry", "file", "status", "old_sha256", "new_sha256"])
            w.writeheader()
            w.writerows(changes)
        if changes:
            t = Table(title=f"Files that differ from the manifest ({fresh})")
            for c in ("entry", "file", "status"):
                t.add_column(c)
            for c in changes[:200]:
                t.add_row(c["entry"], c["file"], f"[red]{c['status']}[/]")
            console.print(t)
            console.print(f"[bold red]{len(changes)} file(s) changed[/]: those entries need a fresh look "
                          f"(details in {out}).")
        else:
            console.print(f"[green]All build files match the manifest.[/] ({out})")

    if requery:
        pipe = Pipeline(cfg, console)
        services = enabled_services(cfg)
        if not services:
            console.print("[yellow]No lookup services configured; skipping the re-query.[/]")
            return 0
        n = sum(pipe.state.requeue_all(s) for s in services)
        console.print(f"Re-querying {n} cached lookup(s) (within today's budgets)…")
        mgr = LookupManager(cfg, pipe.cache, services, refresh=True)
        mgr.start()
        mgr.producer_finished()
        pipe._wait_lookups(mgr)
        for e in discover_entries(cfg.builds_dir):
            lp = local_path(cfg, e.slug)
            if lp.is_file():
                pipe.score(e.slug, json.loads(lp.read_text(encoding="utf-8")))
        paths = build_reports(cfg)
        console.print(f"Reports updated: {paths['xlsx']}, {paths['html']}")
        if paths.get("warning"):
            console.print(f"[yellow]{paths['warning']}[/]")
    return 0


def fetch_rules(cfg: Config, url: str = YARA_FORGE_CORE, console: Console | None = None) -> int:
    console = console or Console()
    dest = cfg.rules_dir / "yara"
    dest.mkdir(parents=True, exist_ok=True)
    console.print(f"Downloading YARA Forge core rules from {url}")
    r = requests.get(url, timeout=120)
    if r.status_code != 200:
        console.print(f"[red]Download failed: HTTP {r.status_code}[/]")
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        zpath = Path(tmp) / "rules.zip"
        zpath.write_bytes(r.content)
        res = unpack_zip(zpath, Path(tmp) / "x", Budget(Limits(max_total_bytes=500 << 20, max_files=1000)), "rules.zip")
        yars = [p for p in res.extracted if p.suffix.lower() in (".yar", ".yara")]
        if not yars:
            console.print("[red]No .yar files in the download.[/]")
            return 1
        for p in yars:
            shutil.copyfile(p, dest / p.name)
            console.print(f"  saved {dest / p.name}")
    console.print("[green]Done.[/] The rules are compiled at the start of each analysis run.")
    return 0
