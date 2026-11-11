"""Platform detection and external tool discovery.

A missing tool never crashes a run: its check is reported as "not run".
"""
from __future__ import annotations

import glob
import importlib.util
import os
import platform as _platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .proc import run_group


def detect_platform(override: str | None = None) -> str:
    if override:
        return override
    system = _platform.system()
    return {"Darwin": "macos", "Windows": "windows"}.get(system, "linux")


def which(name: str) -> str | None:
    """shutil.which, also looking next to the running interpreter (virtualenv bin/Scripts)."""
    venv_bin = Path(sys.executable).parent
    found = shutil.which(name, path=str(venv_bin)) or shutil.which(name)
    if not found and name == "ilspycmd":
        cand = Path.home() / ".dotnet" / "tools" / ("ilspycmd.exe" if os.name == "nt" else "ilspycmd")
        found = str(cand) if cand.exists() else None
    return found


def find_mpcmdrun() -> str | None:
    found = shutil.which("MpCmdRun.exe") or shutil.which("MpCmdRun")
    if found:
        return found
    pd = os.environ.get("ProgramData", r"C:\ProgramData")
    platforms = sorted(glob.glob(os.path.join(pd, "Microsoft", "Windows Defender", "Platform", "*", "MpCmdRun.exe")))
    if platforms:
        return platforms[-1]
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    cand = os.path.join(pf, "Windows Defender", "MpCmdRun.exe")
    return cand if os.path.exists(cand) else None


@dataclass
class ToolSpec:
    key: str
    names: tuple[str, ...]
    purpose: str
    platforms: tuple[str, ...]          # where the check applies
    install: dict[str, str]             # platform -> install hint
    python_module: str | None = None    # for library-based checks
    optional: bool = False


TOOLS: list[ToolSpec] = [
    ToolSpec("itch-dl", ("itch-dl",), "download jam entries", ("macos", "windows", "linux"),
             {"*": "pip install itch-dl"}),
    ToolSpec("7z", ("7zz", "7z", "7za"), "unpack .7z/.rar", ("macos", "windows", "linux"),
             {"macos": "brew install sevenzip", "windows": "winget install 7zip.7zip", "linux": "apt install 7zip"}),
    ToolSpec("clamav", ("clamscan",), "antivirus scan (ClamAV)", ("macos", "linux"),
             {"macos": "brew install clamav && freshclam", "linux": "apt install clamav && freshclam"}),
    ToolSpec("defender", ("MpCmdRun.exe",), "antivirus scan (Microsoft Defender)", ("windows",),
             {"windows": "built into Windows"}),
    ToolSpec("mdatp", ("mdatp",), "antivirus scan (Defender for Mac)", ("macos",),
             {"macos": "needs a Microsoft Defender for Endpoint subscription"}, optional=True),
    ToolSpec("diec", ("diec",), "engine/packer/installer detection", ("macos", "windows", "linux"),
             {"*": "download from github.com/horsicq/DIE-engine/releases and put diec on PATH"}),
    ToolSpec("capa", ("capa",), "executable capabilities", ("macos", "windows", "linux"),
             {"*": "pip install flare-capa (plus capa-rules) or the standalone release"}),
    ToolSpec("yara", (), "YARA rules", ("macos", "windows", "linux"),
             {"*": "pip install yara-python; triage fetch-rules"}, python_module="yara"),
    ToolSpec("pefile", (), "PE imports/sections", ("macos", "windows", "linux"),
             {"*": "pip install pefile"}, python_module="pefile"),
    ToolSpec("signify", (), "Authenticode signatures", ("macos", "windows", "linux"),
             {"*": "pip install signify"}, python_module="signify"),
    ToolSpec("gdre", ("gdre_tools", "gdre_tools.exe", "GDRE_tools"), "Godot recovery", ("macos", "windows", "linux"),
             {"*": "download from github.com/GDRETools/gdsdecomp/releases (gdre_tools on PATH)"}),
    ToolSpec("ilspycmd", ("ilspycmd",), "Unity Mono decompiler", ("macos", "windows", "linux"),
             {"*": "dotnet tool install -g ilspycmd (needs the .NET SDK)"}),
    ToolSpec("pyinstxtractor", ("pyinstxtractor-ng",), "PyInstaller extractor", ("macos", "windows", "linux"),
             {"*": "pip install pyinstxtractor-ng"}),
    ToolSpec("scallop", ("scallop",), "Node SEA extractor", ("macos", "windows", "linux"),
             {"*": "pip install node-sea-scallop"}, optional=True),
    ToolSpec("npx", ("npx",), "@electron/asar (optional; built-in asar reader is used otherwise)",
             ("macos", "windows", "linux"), {"*": "install Node.js"}, optional=True),
]


@dataclass
class ToolStatus:
    key: str
    status: str            # available | missing | skipped
    path: str = ""
    purpose: str = ""
    hint: str = ""
    optional: bool = False


def probe_tools(plat: str, overrides: dict[str, str] | None = None) -> dict[str, ToolStatus]:
    """Find every external tool. `overrides` ([tools.paths] in config.toml) maps a check key to a binary."""
    overrides = overrides or {}
    out: dict[str, ToolStatus] = {}
    for spec in TOOLS:
        hint = spec.install.get(plat) or spec.install.get("*", "")
        if plat not in spec.platforms:
            out[spec.key] = ToolStatus(spec.key, "skipped", purpose=spec.purpose, hint=f"not used on {plat}",
                                       optional=spec.optional)
            continue
        path = ""
        if spec.key in overrides:
            o = overrides[spec.key]
            ok = Path(o).is_file() and os.access(o, os.X_OK)
            out[spec.key] = ToolStatus(spec.key, "available" if ok else "missing", o if ok else "", spec.purpose,
                                       f"[tools.paths] {spec.key} = {o!r} is not an executable file", spec.optional)
            continue
        if spec.python_module:
            path = "python:" + spec.python_module if importlib.util.find_spec(spec.python_module) else ""
        elif spec.key == "defender":
            path = find_mpcmdrun() or ""
        else:
            for n in spec.names:
                path = which(n) or ""
                if path:
                    break
        out[spec.key] = ToolStatus(spec.key, "available" if path else "missing", path, spec.purpose, hint,
                                   spec.optional)
    z = out.get("7z")
    if z and z.status == "available" and not seven_zip_has_rar(z.path):
        z.purpose += " (NO RAR decoder: .rar can't be unpacked; use the official 7-Zip from 7-zip.org)"
    return out


def seven_zip_has_rar(path: str) -> bool:
    """Homebrew's `sevenzip` ships without the RAR codecs: it lists .rar files but can't extract them."""
    try:
        p = run_group([path, "i"], timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return True        # can't tell; don't warn
    codecs = p.stdout.split("Codecs:", 1)[1] if "Codecs:" in p.stdout else ""
    return not codecs or "rar" in codecs.lower()


def tool_version(path: str, args: tuple[str, ...] = ("--version",), timeout: int = 20) -> str:
    if not path or path.startswith("python:"):
        mod = path.removeprefix("python:")
        try:
            m = __import__(mod)
            return str(getattr(m, "__version__", getattr(m, "YARA_VERSION", "")))
        except Exception:  # noqa: BLE001
            return ""
    try:
        p = run_group([path, *args], timeout=timeout)
        text = (p.stdout or p.stderr).strip().splitlines()
        return text[0][:120] if text else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def print_tool_table(statuses: dict[str, ToolStatus], plat: str, console=None) -> None:
    from rich.console import Console
    from rich.table import Table

    console = console or Console()
    table = Table(title=f"External tools ({plat})", show_lines=False)
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Purpose")
    table.add_column("Path / install")
    colors = {"available": "green", "missing": "red", "skipped": "dim"}
    for st in statuses.values():
        status = st.status if not (st.status == "missing" and st.optional) else "missing (optional)"
        color = "yellow" if st.status == "missing" and st.optional else colors[st.status]
        table.add_row(st.key, f"[{color}]{status}[/{color}]", st.purpose, st.path if st.path else st.hint)
    console.print(table)
