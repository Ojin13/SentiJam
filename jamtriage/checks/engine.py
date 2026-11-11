"""Engine fingerprints, wrapper detection, main-executable choice and "extra executables"."""
from __future__ import annotations

import re
from pathlib import Path

from ..models import FileRecord, Finding, Severity
from ..rules import custom_rules
from . import EntryContext

MARKERS: dict[str, bytes] = {
    "godot_pck": b"GDPC",
    "godot_str": b"godotengine.org",
    "pyinstaller": b"MEI\x0c\x0b\x0a\x0b\x0e",
    "pyinstaller_str": b"PYZ-00.pyz",
    "pyinstaller_str2": b"pyi-runtime-tmpdir",
    "pkg": b"pkg/prelude/bootstrap.js",
    "pkg2": b"PAYLOAD_POSITION",
    "nexe": b"<nexe~~sentinel>",
    "node_sea": b"NODE_SEA_BLOB",
    "node_sea_fuse": b"NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2",
    "node_runtime": b"node.js/v",
    "electron": b"Electron/",
    "nwjs": b"nwjs.io",
    "unity": b"UnityPlayer",
    "dotnet": b"mscoree.dll",
    "nsis": b"Nullsoft Install System",
    "nsis2": b"NullsoftInst",
    "inno": b"Inno Setup Setup Data",
    "inno2": b"Inno Setup",
    "upx": b"UPX!",
    "love": b"love2d.org",
    "gamemaker": b"YoYo Games",
    "monogame": b"MonoGame",
}

ENGINE_NAMES = {
    "unity-mono": "Unity (Mono)", "unity-il2cpp": "Unity (IL2CPP)", "unity": "Unity", "godot": "Godot",
    "gamemaker": "GameMaker", "electron": "Electron", "nwjs": "NW.js", "rpgmaker": "RPG Maker",
    "construct": "Construct", "gdevelop": "GDevelop", "love2d": "LÖVE", "renpy": "Ren'Py", "unreal": "Unreal",
    "monogame": "MonoGame/FNA", "defold": "Defold", "pyinstaller": "PyInstaller (Python)",
    "node-pkg": "Node.js (pkg)", "node-nexe": "Node.js (nexe)", "node-sea": "Node.js (SEA)",
    "java": "Java", "dotnet": ".NET", "web": "HTML5",
}
GAME_ENGINES = {"unity-mono", "unity-il2cpp", "unity", "godot", "gamemaker", "electron", "nwjs", "rpgmaker",
                "construct", "gdevelop", "love2d", "renpy", "unreal", "monogame", "defold", "java", "web"}
NODE_PACKERS = {"node-pkg", "node-nexe", "node-sea"}


def scan_markers(path: Path, markers: dict[str, bytes] = MARKERS, max_bytes: int = 512 * 1024 * 1024) -> set[str]:
    """Stream a file once and report which byte markers occur in it."""
    found: set[str] = set()
    overlap = max(len(m) for m in markers.values())
    combined = re.compile(b"|".join(re.escape(m) for m in markers.values()))
    lookup = {m: k for k, m in markers.items()}
    tail = b""
    read = 0
    try:
        with open(path, "rb") as fh:
            while read < max_bytes:
                chunk = fh.read(4 * 1024 * 1024)
                if not chunk:
                    break
                read += len(chunk)
                buf = tail + chunk
                for m in combined.finditer(buf):
                    found.add(lookup[m.group(0)])
                if len(found) == len(markers):
                    break
                tail = buf[-overlap:]
    except OSError:
        pass
    return found


def _paths_lower(ctx: EntryContext) -> list[str]:
    return [r.path.lower() for r in ctx.files]


def detect(ctx: EntryContext) -> None:
    """Fill ctx.info['engine'], ['engines'], ['markers'], ['main_exe'] and raise engine findings."""
    rules = custom_rules(ctx.cfg.rules_dir)
    paths = _paths_lower(ctx)
    engines: set[str] = set()

    def any_path(pred) -> bool:
        return any(pred(p) for p in paths)

    if any_path(lambda p: p.endswith("/unityplayer.dll") or p.endswith("/globalgamemanagers") or p.endswith("/data.unity3d")):
        engines.add("unity")
    if any_path(lambda p: p.endswith("_data/managed/assembly-csharp.dll")):
        engines.add("unity-mono")
    if any_path(lambda p: p.endswith("/gameassembly.dll") or "/il2cpp_data/" in p):
        engines.add("unity-il2cpp")
    if any_path(lambda p: p.endswith(".pck")):
        engines.add("godot")
    if any_path(lambda p: p.endswith("/data.win") or p.endswith("/game.unx") or "/html5game/" in p):
        engines.add("gamemaker")
    if any_path(lambda p: p.endswith("/resources/app.asar") or "/resources/app/package.json" in p):
        engines.add("electron")
    if any_path(lambda p: p.endswith("/package.nw") or p.endswith("/nw.dll") or p.endswith("/nw_elf.dll")):
        engines.add("nwjs")
    if any_path(lambda p: "/js/rpg_core.js" in p or "/js/rmmz_core.js" in p or p.endswith(".rgss3a") or p.endswith(".rgssad")):
        engines.add("rpgmaker")
    if any_path(lambda p: p.endswith("/c3runtime.js") or p.endswith("/c2runtime.js") or p.endswith("/scripts/c3main.js")):
        engines.add("construct")
    if any_path(lambda p: "/gdjs/" in p or p.endswith("/gd.js")):
        engines.add("gdevelop")
    if any_path(lambda p: p.endswith("/love.dll") or p.endswith(".love")):
        engines.add("love2d")
    if any_path(lambda p: "/renpy/" in p or p.endswith(".rpa") or p.endswith(".rpyc")):
        engines.add("renpy")
    if any_path(lambda p: "/engine/binaries/" in p or "/content/paks/" in p):
        engines.add("unreal")
    if any_path(lambda p: p.endswith("/monogame.framework.dll") or p.endswith("/fna.dll")):
        engines.add("monogame")
    if any_path(lambda p: p.endswith("/game.projectc") or p.endswith("/game.darc")):
        engines.add("defold")
    if any_path(lambda p: p.endswith(".jar")):
        engines.add("java")

    # Byte markers in executables (skipping known engine runtime files).
    exe_markers: dict[str, set[str]] = {}
    for rec in ctx.records("pe", "elf", "macho"):
        if rules.is_engine_runtime(rec.path):
            continue
        m = scan_markers(ctx.abspath(rec), max_bytes=int(ctx.cfg.section("tools").get("max_scan_bytes", 256 << 20)) * 2)
        exe_markers[rec.path] = m
        if m & {"pyinstaller", "pyinstaller_str", "pyinstaller_str2"}:
            engines.add("pyinstaller")
            rec.tags.append("pyinstaller")
        if m & {"pkg", "pkg2"}:
            engines.add("node-pkg")
            rec.tags.append("node-pkg")
        if "nexe" in m:
            engines.add("node-nexe")
            rec.tags.append("node-nexe")
        if m & {"node_sea", "node_sea_fuse"}:
            engines.add("node-sea")
            rec.tags.append("node-sea")
        if "godot_pck" in m and "godot_str" in m:
            engines.add("godot")
            rec.tags.append("godot-embedded" if "godot_pck" in m else "godot")
        if m & {"nsis", "nsis2", "inno"}:
            rec.tags.append("installer-exe")
        if "upx" in m:
            rec.tags.append("upx")
        if "electron" in m and "electron" in engines and rec.size > 40 * 1024 * 1024:  # real Electron is ~150 MB
            rec.tags.append("electron-runtime")
        if "love" in m:
            engines.add("love2d")
        if "gamemaker" in m:
            engines.add("gamemaker")
        if "dotnet" in m:
            rec.tags.append("dotnet")
    ctx.info["markers"] = {k: sorted(v) for k, v in exe_markers.items() if v}

    # Web build: any archive with an index.html at its top (or one folder down).
    web_roots = find_web_roots(ctx)
    ctx.info["web_roots"] = web_roots
    if web_roots:
        engines.add("web")

    if engines & {"unity-mono", "unity-il2cpp"}:
        engines.discard("unity")
    ctx.info["engines"] = sorted(engines)
    primary = [e for e in ctx.info["engines"] if e != "web"] or ctx.info["engines"]
    ctx.info["engine"] = ", ".join(ENGINE_NAMES.get(e, e) for e in primary) if primary else "unknown"

    # Installers recognised by bytes (NSIS, Inno Setup).
    for rec in ctx.files:
        if "installer-exe" in rec.tags:
            ctx.add(Finding(rule="file.installer", severity=Severity.HIGH,
                            title="Installer executable (NSIS / Inno Setup) - rule break", file=rec.path,
                            source="engine"))

    # Node.js packer without a game engine fingerprint: High on its own.
    packers = engines & NODE_PACKERS
    if packers and not (engines & (GAME_ENGINES - {"web"})):
        ctx.add(Finding(rule="engine.node_packed", severity=Severity.HIGH,
                        title="Node.js-packed executable with no game engine fingerprint",
                        detail=", ".join(ENGINE_NAMES[p] for p in sorted(packers)), source="engine"))

    executables = [r for r in ctx.records("pe") if r.path.lower().endswith(".exe")]
    ctx.info["main_exe"] = choose_main_exe(ctx, executables)

    if executables and not (engines - {"web", "dotnet"}):
        ctx.add(Finding(rule="engine.none", severity=Severity.MEDIUM, title="No game engine fingerprint",
                        detail=f"{len(executables)} executable(s), engine unknown", source="engine"))
    claimed = (ctx.info.get("claimed_engine") or "").lower()
    if claimed and engines and not any(_claim_matches(claimed, e) for e in engines):
        ctx.add(Finding(rule="engine.mismatch", severity=Severity.MEDIUM,
                        title="Detected engine differs from the one the page claims",
                        detail=f"page says {claimed!r}, detected {ctx.info['engine']}", source="engine"))

    # Extra executables beyond what the engine ships.
    exes = [r for r in executables if not rules.is_helper_exe(r.path.rsplit("/", 1)[-1])
            and not rules.is_engine_runtime(r.path) and "/node_modules/" not in r.path.lower()]
    # Group by build archive: one main exe per platform build is normal.
    by_archive: dict[str, list[FileRecord]] = {}
    for r in exes:
        by_archive.setdefault(r.archive or "builds", []).append(r)
    for arch, group in by_archive.items():
        if len(group) > 1:
            ctx.add(Finding(rule="engine.extra_executables", severity=Severity.MEDIUM,
                            title="More executables than the engine normally ships",
                            file=arch, detail=", ".join(r.path.rsplit("/", 1)[-1] for r in group[:8]),
                            source="engine"))
    # DLL side-loading: a Windows system DLL name shipped next to an executable.
    exe_dirs = {r.path.rsplit("/", 1)[0] for r in executables}
    for r in ctx.files:
        name = r.path.rsplit("/", 1)[-1].lower()
        if name in rules.sideload_names and r.path.rsplit("/", 1)[0] in exe_dirs:
            ctx.add(Finding(rule="engine.dll_sideload", severity=Severity.HIGH,
                            title="System DLL name shipped next to the game exe (possible DLL side-loading)",
                            file=r.path, detail=f"{name} is normally loaded from C:\\Windows\\System32",
                            source="engine"))
    if not any(r.kind in ("pe", "elf", "macho") for r in ctx.files) and not web_roots:
        ctx.info.setdefault("notes", []).append("no executables found")
    ctx.checks["engine"] = "ok"


def _claim_matches(claimed: str, engine: str) -> bool:
    key = engine.split("-")[0]
    aliases = {"unity": ["unity"], "godot": ["godot"], "gamemaker": ["gamemaker", "game maker"],
               "electron": ["electron", "html5", "javascript", "construct", "gdevelop", "phaser"],
               "nwjs": ["nw.js", "rpg maker", "construct", "html5"], "rpgmaker": ["rpg maker"],
               "construct": ["construct"], "gdevelop": ["gdevelop"], "love2d": ["love", "löve"],
               "renpy": ["ren'py", "renpy"], "unreal": ["unreal"], "monogame": ["monogame", "fna", "xna"],
               "defold": ["defold"], "pyinstaller": ["pygame", "python", "pyxel", "arcade"],
               "web": ["html5", "javascript", "phaser", "pixi", "three", "construct", "gdevelop", "godot", "unity"],
               "java": ["java", "libgdx"], "node": ["javascript", "node"]}
    return any(a in claimed for a in aliases.get(key, [key]))


def choose_main_exe(ctx: EntryContext, executables: list[FileRecord]) -> str:
    rules = custom_rules(ctx.cfg.rules_dir)
    cands = [r for r in executables if not rules.is_helper_exe(r.path.rsplit("/", 1)[-1])
             and not rules.is_engine_runtime(r.path) and "/node_modules/" not in r.path.lower()]
    if not cands:
        return ""
    cands.sort(key=lambda r: (r.path.count("/"), -r.size))
    return cands[0].path


def find_web_roots(ctx: EntryContext) -> list[str]:
    """Folders (entry-relative) that hold an HTML5 build: index.html at an archive's top or one level down."""
    roots: list[str] = []
    for rec in ctx.files:
        if rec.origin != "unpacked" or not rec.path.lower().endswith("/index.html"):
            continue
        parts = rec.path.split("/")
        # unpacked/<archive>/index.html  or  unpacked/<archive>/<dir>/index.html
        if len(parts) <= 4:
            folder = "/".join(parts[:-1])
            archive_root = "/".join(parts[:2]).lower() + "/"
            # Electron / NW.js / RPG Maker desktop app folders contain index.html too; they aren't web builds.
            in_archive = [p.lower() for p in _all(ctx) if p.lower().startswith(archive_root)]
            if any(p.endswith(("/nw.dll", "/nw_elf.dll", "/resources/app.asar", "/package.nw", "/libnode.so"))
                   or "/resources/app/" in p for p in in_archive):
                continue
            roots.append(folder)
    return sorted(set(roots))


def _all(ctx: EntryContext) -> list[str]:
    return [r.path for r in ctx.files]
