"""Pipeline steps 2-4: inventory, safe unpacking, hashing, plus per-file red flags."""
from __future__ import annotations

import os
import re
import shutil
from pathlib import Path

from ..entries import Entry
from ..filetypes import classify, read_head
from ..hashing import hash_file
from ..models import FileRecord, Finding, Severity
from ..unpack import Budget, Limits, unpack_recursive, zip_is_encrypted
from . import EntryContext


def _record(ctx: EntryContext, path: Path, origin: str, archive: str = "") -> FileRecord:
    kind, tags = classify(path, read_head(path, 512))
    return FileRecord(path=ctx.relpath(path), size=path.stat().st_size, kind=kind, origin=origin,
                      archive=archive, tags=tags)


FILE_HOSTS = ("mega.nz", "mega.co.nz", "drive.google.com", "docs.google.com", "mediafire.com", "dropbox.com",
              "dropboxusercontent.com", "anonfiles", "gofile.io", "pixeldrain.com", "wetransfer.com", "we.tl",
              "1drv.ms", "onedrive.live.com", "sendspace.com", "file.io", "catbox.moe", "transfer.sh",
              "github.com/.*/releases/download", "discord.com/attachments", "cdn.discordapp.com/attachments")
_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)
_FILE_LINK_RE = re.compile(r"\.(exe|msi|scr|zip|rar|7z|iso|img|bat|cmd|ps1|apk|dmg)(\?|#|$)", re.I)


def page_checks(ctx: EntryContext, entry: Entry, files: list) -> None:
    """Checks on the itch.io page itself (itch-dl metadata.json): outside downloads and failed downloads."""
    meta = entry.metadata if isinstance(entry.metadata, dict) else {}
    ext = meta.get("external_downloads") or []
    for url in [ext] if isinstance(ext, str) else ext if isinstance(ext, list) else []:
        ctx.add(Finding(rule="page.external_download", severity=Severity.HIGH,
                        title="Download hosted outside itch.io (rule break; not downloaded or scanned)",
                        file="metadata.json", detail=str(url)[:200], source="inventory"))
    text = " ".join(str(meta.get(k) or "") for k in ("description",))
    site = entry.root / "site.html"   # itch-dl's copy of the game page
    if site.is_file() and site.stat().st_size < 5 * 1024 * 1024:
        text += " " + site.read_text(encoding="utf-8", errors="replace")
    for url in sorted(set(_URL_RE.findall(text)))[:50]:
        low = url.lower()
        if any(d in low for d in ("itch.io", "itch.zone")):
            continue
        if _FILE_LINK_RE.search(low.split("?")[0]) or any(re.search(h, low) for h in FILE_HOSTS):
            ctx.add(Finding(rule="page.download_link", severity=Severity.HIGH,
                            title="Game page links to a download outside itch.io", file="metadata.json",
                            detail=url[:200], source="inventory"))
    errors = meta.get("errors") or []
    errors = [errors] if isinstance(errors, str) else errors if isinstance(errors, list) else [str(errors)]
    if errors:
        ctx.add(Finding(rule="collect.errors", severity=Severity.MEDIUM,
                        title="itch-dl reported download errors: some files may be missing",
                        file="metadata.json", detail="; ".join(str(e) for e in errors)[:300], source="inventory"))
    if not files:
        ctx.add(Finding(rule="collect.no_files", severity=Severity.HIGH,
                        title="No downloadable files: nothing was analysed (download failed, paid, or external)",
                        source="inventory"))


def inventory(ctx: EntryContext, entry: Entry) -> None:
    """List every downloaded file and flag what's visible before unpacking."""
    ctx.files = [_record(ctx, p, "builds") for p in entry.build_files()]
    for rec in ctx.files:
        if "archive:zip" in rec.tags and zip_is_encrypted(ctx.abspath(rec)):
            rec.tags.append("encrypted")
    page_checks(ctx, entry, ctx.files)
    ctx.checks["inventory"] = "ok"


def unpack(ctx: EntryContext) -> None:
    """Extract every archive into data/unpacked/<entry>/<archive name>/ with the configured limits."""
    limits = Limits.from_config(ctx.cfg.section("unpack"))
    budget = Budget(limits)
    root = ctx.unpacked_root
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)
    new_records: list[FileRecord] = []
    for rec in list(ctx.files):
        if rec.kind != "archive":
            continue
        src = ctx.abspath(rec)
        label = rec.path
        dest = root / src.name
        try:
            result = unpack_recursive(src, dest, budget, label)
        except Exception as exc:  # noqa: BLE001  never lose the other archives' results
            from ..unpack import UnpackResult
            result = UnpackResult(error=f"{type(exc).__name__}: {exc}")
        ctx.findings.extend(result.findings)
        if result.error:
            ctx.add(Finding(rule="archive.unreadable", severity=Severity.HIGH,
                            title="Could not unpack archive: its contents were NOT scanned",
                            file=label, detail=result.error, source="unpack"))
        for p in result.extracted:
            if p.exists():
                new_records.append(_record(ctx, p, "unpacked", archive=label))
    ctx.files.extend(new_records)
    ctx.info["unpack"] = {"files": budget.files, "bytes": budget.total_bytes, "limit_hit": budget.limit_hit}
    ctx.checks["unpack"] = "ok"


def add_unwrapped_files(ctx: EntryContext, paths: list[Path], source: str) -> list[FileRecord]:
    recs = []
    for p in paths:
        if p.is_file() and not p.is_symlink():
            r = _record(ctx, p, "unwrapped", archive=source)
            recs.append(r)
    ctx.files.extend(recs)
    return recs


def hash_all(ctx: EntryContext, records: list[FileRecord] | None = None) -> None:
    for rec in records if records is not None else ctx.files:
        if rec.sha256:
            continue
        p = ctx.abspath(rec)
        try:
            rec.__dict__.update(hash_file(p))
        except FileNotFoundError:
            # Real-time antivirus may quarantine files as they are unpacked: a vanished file is a detection.
            rec.tags.append("vanished")
            ctx.add(Finding(rule="av.vanished", severity=Severity.HIGH,
                            title="File vanished after unpacking (likely quarantined by antivirus)",
                            file=rec.path, source="hash"))
        except OSError as exc:
            ctx.add(Finding(rule="analysis.error", severity=Severity.MEDIUM, title="Could not hash file",
                            file=rec.path, detail=str(exc), source="hash"))
    ctx.checks["hash"] = "ok"


def _in_web_or_app_folder(ctx: EntryContext, rec: FileRecord) -> bool:
    """True if a .js file sits in a web build or an Electron/NW.js/RPG Maker app folder."""
    p = ctx.abspath(rec)
    rel = rec.path.lower()
    if any(x in rel for x in ("/resources/app/", "/www/", "/node_modules/", "/package.nw", "/js/", "app.asar")):
        return True
    for parent in list(p.parents)[:4]:
        try:
            if any(c.suffix.lower() in (".html", ".htm") for c in parent.iterdir()):
                return True
        except OSError:
            break
    return False


def _depth_in_archive(rec: FileRecord) -> int:
    parts = rec.path.split("/")
    # builds/<file> -> 0;  unpacked/<archive>/<file> -> 0;  unpacked/<archive>/<dir>/<file> -> 1
    return max(0, len(parts) - (2 if rec.origin == "builds" else 3))


def file_flags(ctx: EntryContext, records: list[FileRecord] | None = None) -> None:
    """Red flags that follow from file names and types alone."""
    for rec in records if records is not None else ctx.files:
        tags = set(rec.tags)
        name = rec.path.rsplit("/", 1)[-1]
        if "double-extension" in tags or "rtlo-filename" in tags:
            ctx.add(Finding(rule="file.double_extension", severity=Severity.HIGH,
                            title="Double extension or disguised file name", file=rec.path, detail=name,
                            source="inventory"))
        if "pe-disguised" in tags:
            ctx.add(Finding(rule="file.disguised_executable", severity=Severity.HIGH,
                            title="Windows executable hidden behind a non-executable extension",
                            file=rec.path, source="inventory"))
        if "dangerous-script" in tags and rec.origin != "unwrapped":
            ext = os.path.splitext(name)[1].lower()
            if ext in (".js", ".jse") and (_in_web_or_app_folder(ctx, rec) or _depth_in_archive(rec) > 1):
                pass  # JavaScript in a web build or app folder is normal; the web/code checks read it.
            else:
                ctx.add(Finding(rule="file.script", severity=Severity.HIGH,
                                title="Script or shortcut file Windows runs on double-click",
                                file=rec.path, detail=ext, source="inventory"))
        if "launcher-script" in tags and rec.origin != "unwrapped":
            ctx.add(Finding(rule="file.launcher", severity=Severity.MEDIUM, title=".bat/.cmd launcher",
                            file=rec.path, source="inventory"))
        if "disk-image" in tags:
            ctx.add(Finding(rule="file.disk_image", severity=Severity.HIGH,
                            title="Disk image (.iso/.img/.vhd): rule break, often used to bypass Windows "
                                  "Mark-of-the-Web warnings", file=rec.path, source="inventory"))
        if "installer" in tags:
            ctx.add(Finding(rule="file.installer", severity=Severity.HIGH, title="Installer package (rule break)",
                            file=rec.path, source="inventory"))
        if "macos" in tags and rec.kind in ("macho", "macos", "archive") and rec.origin != "unwrapped":
            if not ctx.info.get("_macos_flagged"):
                ctx.info["_macos_flagged"] = True
                ctx.add(Finding(rule="file.macos_live", severity=Severity.INFO,
                                title="macOS build present: it can run on a Mac, never double-click it",
                                file=rec.path, source="inventory"))
