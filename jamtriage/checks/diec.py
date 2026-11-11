"""Detect It Easy: compiler, packer, installer and engine identification (`diec -j -d <file>`)."""
from __future__ import annotations

import json

from ..models import Finding, Severity
from . import EntryContext, ToolError, run_tool, trusted_runtime

INSTALLER_WORDS = ("nsis", "nullsoft", "inno setup", "installshield", "wise installer", "install4j",
                   "advanced installer", "setup factory", "smart install maker", "clickteam install")
PACKER_TYPES = {"packer", "protector", "cryptor", "joiner"}


def parse_diec(text: str) -> list[dict]:
    """Return a flat list of {type, name, version, string} from diec JSON output."""
    try:
        data = json.loads(text[text.find("{"):]) if "{" in text else {}
    except json.JSONDecodeError:
        return []
    out = []

    def walk(node):
        if isinstance(node, dict):
            if "type" in node and "name" in node:
                out.append({k: str(node.get(k, "")) for k in ("type", "name", "version", "string")})
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(data)
    return out


def run(ctx: EntryContext) -> None:
    if not ctx.cfg.check_enabled("diec"):
        return
    exe = ctx.tool("diec")
    if not exe:
        ctx.not_run("diec", "diec not installed")
        return
    timeout = int(ctx.cfg.section("tools").get("diec_timeout", 120))
    results = ctx.info.setdefault("diec", {})
    for rec in ctx.records("pe", "elf", "macho"):
        if "vanished" in rec.tags or trusted_runtime(rec):
            continue
        try:
            p = run_tool([exe, "-j", "-d", str(ctx.abspath(rec))], timeout=timeout)
        except ToolError as exc:
            ctx.error("diec", str(exc), rec.path)
            continue
        detects = parse_diec(p.stdout)
        results[rec.path] = [d["string"] or f"{d['type']}: {d['name']} {d['version']}".strip() for d in detects]
        for d in detects:
            typ, name = d["type"].lower(), d["name"].lower()
            if typ in PACKER_TYPES and not rec.path.lower().endswith("/node_modules/"):
                rec.tags.append("packed")
                ctx.add(Finding(rule="pe.packed", severity=Severity.MEDIUM, title=f"Packed executable ({d['name']})",
                                file=rec.path, detail=d["string"] or d["name"], source="diec"))
            if typ in ("installer", "sfx") or any(w in name for w in INSTALLER_WORDS):
                rec.tags.append("installer-exe")
                ctx.add(Finding(rule="file.installer", severity=Severity.HIGH,
                                title=f"Installer executable ({d['name']}) - rule break", file=rec.path,
                                source="diec"))
            if "pyinstaller" in name and "pyinstaller" not in rec.tags:
                rec.tags.append("pyinstaller")
            if "electron" in name and rec.size > 40 * 1024 * 1024 and "electron-runtime" not in rec.tags:
                rec.tags.append("electron-runtime")
            if "godot" in name:
                rec.tags.append("godot")
    ctx.checks["diec"] = "ok"
