"""Unwrapping: pull the game's own code out of executables and engine packs, without running anything.

Godot -> GDRE Tools, Unity Mono -> ilspycmd, Electron/NW.js -> built-in asar reader (or npx @electron/asar),
PyInstaller -> pyinstxtractor-ng, Node SEA -> scallop, pkg/nexe -> string carving of the PE overlay.
Output goes to data/unwrapped/<entry>/<extractor>/...
"""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import struct
from pathlib import Path

from ..models import Finding, Severity
from ..unpack import safe_member_name
from . import EntryContext, ToolError, run_tool, trusted_runtime
from .inventory import add_unwrapped_files

# .NET assemblies that are frameworks/libraries rather than the game's own code.
DOTNET_LIBRARY_PREFIXES = ("system.", "microsoft.", "mono.", "unity", "unityengine", "godotsharp", "godotplugins",
                           "monogame.", "fna", "sdl2-cs", "newtonsoft.", "netstandard", "mscorlib", "windowsbase",
                           "presentationcore", "presentationframework", "steamworks.", "facepunch.", "nlog",
                           "sharpdx", "opentk", "naudio", "nvorbis", "dotnetzip", "ionic.", "protobuf", "google.",
                           "assembly-csharp-firstpass", "0harmony", "bepinex", "xna", "nuget.", "runtime.", "api-ms-")
MAX_DOTNET_DECOMPILE = 15
NOT_INSPECTABLE = {"unity-il2cpp": "Unity IL2CPP", "unreal": "Unreal (native C++)",
                   "gamemaker": "GameMaker (YYC/VM bytecode)", "defold": "Defold (native)"}


# --------------------------------------------------------------------------- asar

class AsarError(Exception):
    pass


def read_asar_header(path: Path) -> tuple[dict, int]:
    with open(path, "rb") as fh:
        head = fh.read(16)
        if len(head) < 16:
            raise AsarError("file too short")
        size_pickle_payload, header_size = struct.unpack("<II", head[:8])
        if size_pickle_payload != 4 or header_size > 512 * 1024 * 1024:
            raise AsarError("not an asar archive")
        _payload_size, json_len = struct.unpack("<II", head[8:16])
        if json_len > header_size:
            raise AsarError("corrupt asar header")
        raw = fh.read(json_len)
    try:
        header = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AsarError(f"bad asar header JSON: {exc}") from exc
    return header, 8 + header_size


def extract_asar(path: Path, dest: Path, max_total: int = 2 * 1024**3, max_files: int = 50_000,
                 problems: list[str] | None = None) -> list[Path]:
    """Built-in, read-only asar extractor with the same path-safety rules as the archive unpacker.

    Hostile headers (wrong types, absurd nesting, bad offsets, colliding names) never abort the whole
    extraction: what can be extracted is, and everything that couldn't be is listed in `problems`.
    """
    from ..unpack import _free_target, _safe_target
    problems = problems if problems is not None else []
    header, base = read_asar_header(path)
    archive_size = path.stat().st_size
    out: list[Path] = []
    total = 0
    stack: list[tuple[dict, str, int]] = [(header, "", 0)]
    while stack:
        node, prefix, depth = stack.pop()
        files = node.get("files") if isinstance(node, dict) else None
        if not isinstance(files, dict):
            continue
        if depth > 64:
            problems.append(f"{prefix}: nested too deeply")
            continue
        for name, item in files.items():
            raw = f"{prefix}/{name}" if prefix else str(name)
            rel = safe_member_name(raw)
            if rel is None or not isinstance(item, dict):
                problems.append(f"{raw[:120]}: unsafe name or malformed entry")
                continue
            if "files" in item:
                stack.append((item, rel, depth + 1))
                continue
            if item.get("link") or item.get("unpacked"):
                continue  # links are skipped; unpacked files already live next to app.asar
            try:
                size, offset = int(item.get("size", 0)), int(item.get("offset", 0))
            except (TypeError, ValueError):
                problems.append(f"{rel}: bad size/offset")
                continue
            if size < 0 or offset < 0 or base + offset + size > archive_size:
                problems.append(f"{rel}: points outside the archive")
                continue
            if total + size > max_total or len(out) >= max_files:
                problems.append(f"extraction limit reached at {rel}; the rest was NOT extracted")
                return out
            target = _safe_target(dest, rel)
            if target is None:
                problems.append(f"{rel}: unsafe target path")
                continue
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                target, _ = _free_target(target)
                with open(path, "rb") as src, open(target, "wb") as dst:
                    src.seek(base + offset)
                    remaining = size
                    while remaining:
                        chunk = src.read(min(remaining, 1 << 20))
                        if not chunk:
                            break
                        dst.write(chunk)
                        remaining -= len(chunk)
                os.chmod(target, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
            except OSError as exc:   # e.g. a file and a folder with the same name
                problems.append(f"{rel}: {type(exc).__name__}: {exc}")
                continue
            total += size
            out.append(target)
    return out


def build_asar(files: dict[str, bytes], out: Path) -> None:
    """Write a minimal asar archive (used by the self-test and unit tests)."""
    tree: dict = {"files": {}}
    blobs, offset = [], 0
    for rel, data in files.items():
        node = tree
        parts = rel.split("/")
        for d in parts[:-1]:
            node = node["files"].setdefault(d, {"files": {}})
        node["files"][parts[-1]] = {"size": len(data), "offset": str(offset)}
        blobs.append(data)
        offset += len(data)
    js = json.dumps(tree, separators=(",", ":")).encode()
    pad = (4 - len(js) % 4) % 4
    payload = struct.pack("<I", len(js)) + js + b"\0" * pad
    header_pickle = struct.pack("<I", len(payload)) + payload
    out.write_bytes(struct.pack("<II", 4, len(header_pickle)) + header_pickle + b"".join(blobs))


# --------------------------------------------------------------------------- carving

def carve_js(path: Path, start: int, dest: Path, max_bytes: int = 256 * 1024 * 1024) -> Path | None:
    """Carve readable text runs (min 12 chars) from the region a Node packer appends to the runtime."""
    rx = re.compile(rb"[\x09\x0a\x0d\x20-\x7e]{12,}")
    pieces: list[bytes] = []
    with open(path, "rb") as fh:
        fh.seek(start)
        data = fh.read(max_bytes)
    for m in rx.finditer(data):
        pieces.append(m.group(0))
    if not pieces:
        return None
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(b"\n".join(pieces))
    return dest


# --------------------------------------------------------------------------- dispatcher

APPENDED_MAGIC = [(b"7z\xbc\xaf\x27\x1c", "7z"), (b"Rar!\x1a\x07", "rar"), (b"PK\x03\x04", "zip"),
                  (b"\xef\xbe\xad\xdeNullsoftInst", "nsis"), (b"Inno Setup", "inno"), (b"zlb\x1a", "inno")]


def appended_archive(path: Path, pe_info: dict) -> tuple[str, int] | None:
    """(format, offset) of an archive/installer payload appended to a PE (self-extractor, fused LÖVE game...)."""
    start = pe_info.get("overlay_offset")
    if not start:
        return None
    cert_off, cert_size = pe_info.get("cert_offset") or 0, pe_info.get("cert_size") or 0
    if cert_off and cert_off == start:
        start += cert_size   # the overlay is just the Authenticode signature
    try:
        with open(path, "rb") as fh:
            fh.seek(start)
            head = fh.read(4096)
    except OSError:
        return None
    for magic, fmt in APPENDED_MAGIC:
        i = head.find(magic)
        if 0 <= i <= 512:
            return fmt, start + i
    return None


OVERLAY_MIN_BYTES = 1 << 20      # appended data at least this big...
OVERLAY_MIN_SHARE = 0.25         # ...and at least this share of the file counts as a hidden payload


def unknown_overlay(path: Path, pe_info: dict) -> tuple[int, float, bytes] | None:
    """(size, share of the file, first bytes) of a large appended payload in no format we can unpack.
    The Authenticode signature (which also lives in the overlay) is not counted."""
    start = pe_info.get("overlay_offset")
    if not start:
        return None
    try:
        total = path.stat().st_size
    except OSError:
        return None
    size = total - start
    cert_off, cert_size = pe_info.get("cert_offset") or 0, pe_info.get("cert_size") or 0
    if cert_off >= start:
        size -= cert_size
    if size < OVERLAY_MIN_BYTES or size / max(total, 1) < OVERLAY_MIN_SHARE:
        return None
    try:
        with open(path, "rb") as fh:
            fh.seek(start + (cert_size if cert_off == start else 0))
            head = fh.read(16)
    except OSError:
        head = b""
    return size, size / total, head


def _fail(ctx: EntryContext, what: str, file: str, why: str) -> None:
    ctx.add(Finding(rule="unwrap.failed", severity=Severity.MEDIUM,
                    title=f"Extractor failed on a format it should handle ({what})", file=file,
                    detail=why[:300], source="unwrap"))


def _new_files(dest: Path) -> list[Path]:
    """Regular files an extractor produced. Symlinks it may have created are removed, never followed."""
    if not dest.exists():
        return []
    out = []
    for p in dest.rglob("*"):
        if p.is_symlink():
            p.unlink(missing_ok=True)
        elif p.is_file():
            out.append(p)
    return out


def run(ctx: EntryContext) -> None:
    if not ctx.cfg.check_enabled("unwrap"):
        return
    root = ctx.unwrapped_root
    if root.exists():
        shutil.rmtree(root)
    timeout = int(ctx.cfg.section("tools").get("extractor_timeout", 600))
    engines = set(ctx.info.get("engines", []))
    done: dict[str, list[str]] = {}
    added = []
    n = 0

    def dest_for(kind: str) -> Path:
        nonlocal n
        n += 1
        d = root / kind / f"{n:02d}"
        d.mkdir(parents=True, exist_ok=True)
        return d

    records = list(ctx.files)
    for rec in records:
        try:
            if "vanished" in rec.tags or rec.origin == "unwrapped":
                continue
            path = ctx.abspath(rec)
            low = rec.path.lower()

            # Electron / NW.js app.asar
            if low.endswith(".asar"):
                d = dest_for("asar")
                problems: list[str] = []
                try:
                    files = extract_asar(path, d, problems=problems)
                    added += add_unwrapped_files(ctx, files, rec.path)
                    done.setdefault("asar", []).append(rec.path)
                except (AsarError, OSError, ValueError, RecursionError) as exc:
                    ctx.add(Finding(rule="archive.unreadable", severity=Severity.HIGH,
                                    title="Electron app.asar could not be read: the app code was NOT scanned",
                                    file=rec.path, detail=str(exc)[:300], source="unwrap"))
                if problems:
                    ctx.add(Finding(rule="archive.unextracted", severity=Severity.HIGH,
                                    title=f"{len(problems)} entr{'y' if len(problems) == 1 else 'ies'} in app.asar "
                                          f"could not be extracted and were NOT scanned",
                                    file=rec.path, detail="; ".join(problems[:5])[:300], source="unwrap"))
                continue

            # Godot .pck (or an exe with an embedded pack and no separate .pck)
            is_pck = low.endswith(".pck")
            embedded = "godot-embedded" in rec.tags and not any(r.path.lower().endswith(".pck") for r in records)
            if is_pck or embedded:
                exe = ctx.tool("gdre")
                if not exe:
                    ctx.not_run("unwrap:godot", "gdre_tools not installed")
                    continue
                d = dest_for("godot")
                try:
                    p = run_tool([exe, "--headless", f"--recover={path}", f"--output-dir={d}"], timeout=timeout)
                    files = _new_files(d)
                    if not files:
                        _fail(ctx, "Godot", rec.path, (p.stderr or p.stdout).strip()[-300:] or f"exit {p.returncode}")
                    added += add_unwrapped_files(ctx, files, rec.path)
                    done.setdefault("godot", []).append(rec.path)
                except ToolError as exc:
                    _fail(ctx, "Godot", rec.path, str(exc))
                continue

            # PyInstaller
            if rec.kind == "pe" and "pyinstaller" in rec.tags:
                exe = ctx.tool("pyinstxtractor")
                if not exe:
                    ctx.not_run("unwrap:pyinstaller", "pyinstxtractor-ng not installed")
                    continue
                d = dest_for("pyinstaller")
                try:
                    p = run_tool([exe, str(path)], timeout=timeout, cwd=d)
                    files = _new_files(d)
                    if not files:
                        _fail(ctx, "PyInstaller", rec.path, (p.stderr or p.stdout).strip()[-300:])
                    m = re.search(r"Possible entry point:\s*(\S+)", p.stdout or "")
                    if m:
                        ctx.info.setdefault("pyinstaller_entry", []).append(m.group(1))
                    added += add_unwrapped_files(ctx, files, rec.path)
                    done.setdefault("pyinstaller", []).append(rec.path)
                except ToolError as exc:
                    _fail(ctx, "PyInstaller", rec.path, str(exc))
                continue

            # Node SEA (scallop), pkg / nexe (carving)
            if rec.kind == "pe" and rec.tags and {"node-sea", "node-pkg", "node-nexe"} & set(rec.tags):
                d = dest_for("node")
                got: list[Path] = []
                if "node-sea" in rec.tags and ctx.tool("scallop"):
                    copy = d / path.name
                    shutil.copyfile(path, copy)  # scallop writes next to its input; give it a private copy
                    try:
                        run_tool([ctx.tool("scallop"), "unpack", str(copy)], timeout=timeout, cwd=d)
                    except ToolError as exc:
                        ctx.info.setdefault("notes", []).append(f"scallop: {exc}")
                    copy.unlink(missing_ok=True)
                    got = _new_files(d)
                if not got:
                    start = 0
                    pe_info = (ctx.info.get("pe") or {}).get(rec.path) or {}
                    start = pe_info.get("overlay_offset") or 0
                    carved = carve_js(path, start, d / "carved.js")
                    got = [carved] if carved else []
                added += add_unwrapped_files(ctx, got, rec.path)
                done.setdefault("node", []).append(rec.path)
                continue

            # .NET: Unity Mono's Assembly-CSharp.dll and other non-engine managed DLLs, plus any other .NET
            # executable or assembly that isn't a known framework (MonoGame/FNA/Godot C# games, and C# stealers).
            name = low.rsplit("/", 1)[-1]
            is_dotnet = bool(((ctx.info.get("pe") or {}).get(rec.path) or {}).get("is_dotnet"))
            unity_managed = "_data/managed/" in low and low.endswith(".dll")
            other_dotnet = (is_dotnet and low.endswith((".exe", ".dll")) and not name.startswith(DOTNET_LIBRARY_PREFIXES)
                            and "/node_modules/" not in low)
            if rec.kind == "pe" and (unity_managed or other_dotnet) and not trusted_runtime(rec):
                exe = ctx.tool("ilspycmd")
                if not exe:
                    ctx.not_run("unwrap:dotnet", "ilspycmd not installed")
                    continue
                if len(done.get("dotnet", [])) >= MAX_DOTNET_DECOMPILE:
                    ctx.info.setdefault("notes", []).append(f"not decompiled (limit {MAX_DOTNET_DECOMPILE}): {rec.path}")
                    continue
                d = dest_for("dotnet")
                try:
                    p = run_tool([exe, "-o", str(d), str(path)], timeout=timeout)
                    files = _new_files(d)
                    if not files:
                        _fail(ctx, ".NET", rec.path, (p.stderr or p.stdout).strip()[-300:])
                    added += add_unwrapped_files(ctx, files, rec.path)
                    done.setdefault("dotnet", []).append(rec.path)
                except ToolError as exc:
                    _fail(ctx, ".NET", rec.path, str(exc))
                continue
        except Exception as exc:  # noqa: BLE001  one bad file must not stop the other extractors
            _fail(ctx, "unwrap", rec.path, f"{type(exc).__name__}: {exc}")

    # Archives/installers glued onto an executable (SFX droppers, fused LÖVE games, NSIS/Inno installers).
    from ..unpack import Budget, Limits, unpack_recursive
    budget = Budget(Limits.from_config(ctx.cfg.section("unpack")))
    handled = {p for paths in done.values() for p in paths}     # extracted by a format-specific extractor
    for rec in records:
        if rec.kind != "pe" or "vanished" in rec.tags or rec.origin == "unwrapped":
            continue
        try:
            pe_info = (ctx.info.get("pe") or {}).get(rec.path) or {}
            found = appended_archive(ctx.abspath(rec), pe_info)
            if not found:
                hidden = None if rec.path in handled else unknown_overlay(ctx.abspath(rec), pe_info)
                if hidden:
                    size, share, head = hidden
                    magic = "".join(chr(b) if 32 <= b < 127 else "." for b in head[:8])
                    ctx.add(Finding(rule="pe.overlay_unscanned", severity=Severity.HIGH,
                                    title=f"{size / 1048576:.0f} MB of data in an unknown format appended to the "
                                          f"executable ({share:.0%} of the file): NOT unpacked or scanned",
                                    file=rec.path, detail=f"starts with '{magic}'; a custom packer or bundler. "
                                    "Ask for an unpacked build, or run it in a sandbox", source="unwrap"))
                continue
            fmt, offset = found
            legit_love = fmt == "zip" and "love2d" in engines
            if fmt == "inno":
                ctx.add(Finding(rule="pe.installer_unscanned", severity=Severity.HIGH,
                                title="Inno Setup installer: its contents could NOT be unpacked and scanned",
                                file=rec.path, detail="install it in the sandbox VM or ask for a plain zip",
                                source="unwrap"))
                continue
            ctx.add(Finding(rule="pe.appended_archive",
                            severity=Severity.LOW if legit_love else (Severity.MEDIUM if fmt in ("zip", "nsis")
                                                                      else Severity.HIGH),
                            title=("Fused LÖVE game (zip appended to the runtime)" if legit_love else
                                   "Installer (NSIS)" if fmt == "nsis" else
                                   f"Self-extracting archive: {fmt} data appended to an executable"),
                            file=rec.path, detail=f"payload at offset {offset}; unpacked and scanned",
                            source="unwrap"))
            d = dest_for("appended")
            if fmt == "nsis":
                src, carved = ctx.abspath(rec), None      # 7-Zip reads NSIS installers from the exe itself
            else:
                carved = d.parent / f"{d.name}.payload.{fmt}"   # outside d, so it isn't picked up as a file
                with open(ctx.abspath(rec), "rb") as fi, open(carved, "wb") as fo:
                    fi.seek(offset)
                    shutil.copyfileobj(fi, fo, 1024 * 1024)
                src = carved
            try:
                r = unpack_recursive(src, d, budget, rec.path + "!appended", fmt="7z" if fmt == "nsis" else fmt)
            finally:
                if carved:
                    carved.unlink(missing_ok=True)
            if r.error or not _new_files(d):
                ctx.add(Finding(rule="archive.unreadable", severity=Severity.HIGH,
                                title="Appended archive could not be unpacked: its contents were NOT scanned",
                                file=rec.path, detail=(r.error or "no files extracted")[:300], source="unwrap"))
            ctx.findings.extend(r.findings)
            added += add_unwrapped_files(ctx, _new_files(d), rec.path)
            done.setdefault("appended", []).append(rec.path)
        except Exception as exc:  # noqa: BLE001
            _fail(ctx, "appended archive", rec.path, f"{type(exc).__name__}: {exc}")

    ctx.info["unwrapped"] = done
    ctx.info["_unwrapped_new"] = [r.path for r in added]
    inspectable = bool(done) or engines & {"electron", "nwjs", "rpgmaker", "construct", "gdevelop", "web", "renpy",
                                           "love2d", "java"}
    native = [NOT_INSPECTABLE[e] for e in sorted(engines) if e in NOT_INSPECTABLE]
    has_exe = any(r.kind in ("pe", "elf", "macho") for r in ctx.files)
    if native or (has_exe and not inspectable and not engines & {"godot", "unity-mono", "pyinstaller"}):
        # (decompiled .NET counts as inspectable via `done`)
        ctx.add(Finding(rule="unwrap.not_inspectable", severity=Severity.INFO, title="Code not inspectable",
                        detail=", ".join(native) or "native code; relying on the other checks", source="unwrap"))
    ctx.checks["unwrap"] = "ok"
