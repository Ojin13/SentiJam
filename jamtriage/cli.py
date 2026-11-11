"""jam-triage command line: triage <command> [options]."""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from rich.console import Console

from . import __version__
from .config import load_config
from .tools import detect_platform, print_tool_table, probe_tools

console = Console()
ONLY_CHOICES = ["defender", "clamav", "mdatp", "antivirus", "yara", "capa", "diec", "pe", "strings", "code", "web",
                "lookups"]


def _cfg(args):
    cfg = load_config(Path(args.config).resolve() if args.config else None)
    cfg.platform = detect_platform(getattr(args, "platform", None))
    if getattr(args, "debug", False):
        cfg.raw["debug"] = True
    return cfg


def cmd_tools(args) -> int:
    cfg = _cfg(args)
    print_tool_table(probe_tools(cfg.platform, cfg.tool_paths()), cfg.platform, console)
    keys = {k: bool(cfg.key(k)) for k in ("ITCH_API_KEY", "VT_API_KEY", "MB_AUTH_KEY", "MD_API_KEY", "HA_API_KEY")}
    console.print("API keys: " + ", ".join(f"{k}={'set' if v else '[dim]missing[/]'}" for k, v in keys.items()))
    yara_dir = cfg.rules_dir / "yara"
    n = len([*yara_dir.glob("*.yar"), *yara_dir.glob("*.yara")]) if yara_dir.is_dir() else 0
    console.print(f"YARA rule files in {yara_dir}: {n}" + ("" if n else "  (run `triage fetch-rules`)"))
    return 0


def cmd_collect(args) -> int:
    from .collect import collect
    return collect(_cfg(args), args.jam_url, Path(args.dest).resolve() if args.dest else None, console)


def cmd_analyze(args) -> int:
    from .entries import discover_entries
    from .pipeline import Pipeline

    cfg = _cfg(args)
    cfg.only = set(args.only or [])
    server = None
    if args.dashboard:
        from .dashboard import DashboardServer
        server = DashboardServer(cfg)
        url = server.start()
        console.print(f"[bold green]Dashboard:[/] {url}")
    pipe = Pipeline(cfg, console)
    entries = discover_entries(cfg.builds_dir)
    if args.entry:
        wanted = set(args.entry)
        entries = [e for e in entries if e.slug in wanted]
    try:
        results = pipe.analyze(entries, force=args.force, wait_for_lookups=not args.no_wait, sandbox=args.sandbox,
                               workers=args.workers)
    except KeyboardInterrupt:
        console.print("[yellow]Interrupted. Progress is saved; run the same command to continue.[/]")
        return 130
    tally: dict[str, int] = {}
    for r in results:
        tally[r["verdict"]] = tally.get(r["verdict"], 0) + 1
    console.print("Verdicts: " + ", ".join(f"{k}: {v}" for k, v in sorted(tally.items())) if tally else "No results.")
    console.print("Next: [bold]triage report[/] to write out/report.xlsx, out/report.html and out/manifest.csv")
    if server:
        console.print("[dim]Dashboard stays up; press Ctrl+C to quit.[/]")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            server.stop()
    return 0


def cmd_report(args) -> int:
    from .report import build_reports
    paths = build_reports(_cfg(args))
    for k, p in paths.items():
        console.print(f"[yellow]{p}[/]" if k == "warning" else f"{k:9} {p}")
    return 0


def cmd_recheck(args) -> int:
    from .collect import recheck
    return recheck(_cfg(args), Path(args.fresh).resolve() if args.fresh else None, args.collect, console,
                   requery=not args.no_requery)


def cmd_upload(args) -> int:
    from .sandbox.detonate import Refused, upload
    try:
        return upload(_cfg(args), args.entry, args.file, args.confirm_public, console)
    except Refused as exc:
        console.print(f"[red]Refused:[/] {exc}")
        return 3


def cmd_sandbox(args) -> int:
    from .sandbox import virustotal as vtsandbox
    cfg = _cfg(args)
    providers = list(vtsandbox.PROVIDERS) if args.provider == "all" else [args.provider]
    if args.action == "status":
        vtsandbox.status(cfg, console, tuple(providers))
        return 0
    if args.action != "plan":
        ready = vtsandbox.available(cfg)
        for p in [p for p in providers if p not in ready]:
            console.print(f"[yellow]{p}: API key not set; skipped.[/]")
        providers = [p for p in providers if p in ready]
    return vtsandbox.run(cfg, console, args.action, providers, args.entry, force=args.force)


def cmd_detonate(args) -> int:
    from .sandbox.detonate import Refused, detonate
    try:
        return detonate(_cfg(args), args.entry, args.confirm_public, console, file=args.file)
    except Refused as exc:
        console.print(f"[red]Refused:[/] {exc}")
        return 3


def cmd_selftest(args) -> int:
    from .selftest import run_selftest
    return 0 if run_selftest(_cfg(args), console, keep=args.keep, offline=args.offline) else 1


def cmd_fetch_rules(args) -> int:
    from .collect import fetch_rules
    return fetch_rules(_cfg(args), console=console)


def cmd_dashboard(args) -> int:
    from .dashboard import DashboardServer
    server = DashboardServer(_cfg(args))
    console.print(f"[bold green]Dashboard:[/] {server.start()}  (Ctrl+C to quit)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="triage", description="Malware triage for game jam submissions. "
                                "Never executes a submission.")
    p.add_argument("--version", action="version", version=f"jam-triage {__version__}")
    p.add_argument("--config", help="path to config.toml (default: ./config.toml)")
    p.add_argument("--platform", choices=["macos", "windows", "linux"], help="override OS detection")
    p.add_argument("--debug", action="store_true", help="print tracebacks for failing checks")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("selftest", help="run the pipeline on harmless fixtures and check every rule fires")
    s.add_argument("--keep", action="store_true", help="keep unpacked fixture files in data/selftest/")
    s.add_argument("--offline", action="store_true", help="skip the VirusTotal part")
    s.set_defaults(func=cmd_selftest)

    s = sub.add_parser("collect", help="download every jam entry with itch-dl into data/builds/")
    s.add_argument("jam_url")
    s.add_argument("--dest", help="download folder (default: data/builds)")
    s.set_defaults(func=cmd_collect)

    s = sub.add_parser("analyze", help="inventory, unpack, hash, lookups, local checks; resumable")
    s.add_argument("--dashboard", action="store_true", help="serve the live dashboard on 127.0.0.1:8787")
    s.add_argument("--only", action="append", choices=ONLY_CHOICES,
                   help="rerun only these checks on saved results (repeatable), e.g. --only defender in a Windows VM")
    s.add_argument("--entry", action="append", help="analyse only this entry slug (repeatable)")
    s.add_argument("--force", action="store_true", help="re-analyse entries even if nothing changed")
    s.add_argument("--no-wait", action="store_true", help="don't wait for pending hash lookups")
    s.add_argument("--workers", type=int, metavar="N",
                   help="analyse N entries at the same time (default: [analysis] workers in config.toml)")
    s.add_argument("--sandbox", action="store_true",
                   help="opt-in: also submit consenting entries to the VirusTotal and Hybrid Analysis sandboxes "
                        "and collect ready results (public; much slower than the static checks)")
    s.set_defaults(func=cmd_analyze)

    s = sub.add_parser("report", help="write out/report.xlsx, out/report.html and out/manifest.csv")
    s.set_defaults(func=cmd_report)

    s = sub.add_parser("recheck", help="re-query cached hashes and compare the manifest with a fresh download")
    s.add_argument("--collect", metavar="JAM_URL", help="download a fresh copy into data/builds-recheck first")
    s.add_argument("--fresh", help="folder with a fresh itch-dl download to compare (default: data/builds)")
    s.add_argument("--no-requery", action="store_true", help="only compare files, don't re-query hashes")
    s.set_defaults(func=cmd_recheck)

    s = sub.add_parser("upload", help="opt-in: upload one file of an entry to VirusTotal (makes it public)")
    s.add_argument("entry")
    s.add_argument("file", help="file path as shown in the report (e.g. unpacked/game.zip/Game.exe)")
    s.add_argument("--confirm-public", action="store_true", help="the entrant agreed to public uploads")
    s.set_defaults(func=cmd_upload)

    s = sub.add_parser("detonate", help="opt-in, one entry: VirusTotal behaviour report and/or a Hybrid "
                                        "Analysis run (public)")
    s.add_argument("entry")
    s.add_argument("--file", help="file to run instead of the detected main executable")
    s.add_argument("--confirm-public", action="store_true", help="the entrant agreed to public uploads")
    s.set_defaults(func=cmd_detonate)

    s = sub.add_parser("sandbox", help="batch: run consenting entries through the VirusTotal and Hybrid "
                                       "Analysis sandboxes (public)")
    s.add_argument("action", choices=["plan", "upload", "collect", "status"],
                   help="plan = dry run with request estimate; upload; collect = fetch results later; status")
    s.add_argument("--entry", action="append", help="only this entry slug (repeatable)")
    s.add_argument("--force", action="store_true", help="collect: fetch again even if already collected")
    s.add_argument("--provider", choices=["all", "virustotal", "hybrid"], default="all",
                   help="which sandbox (default: both)")
    s.set_defaults(func=cmd_sandbox)

    s = sub.add_parser("tools", help="show which external tools and API keys are available")
    s.set_defaults(func=cmd_tools)

    s = sub.add_parser("fetch-rules", help="download the YARA Forge core rule set into rules/yara/")
    s.set_defaults(func=cmd_fetch_rules)

    s = sub.add_parser("dashboard", help="serve the dashboard for an existing data/ folder")
    s.set_defaults(func=cmd_dashboard)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
