"""capa: plain-language capabilities of the main executable (`capa -j <file>`)."""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading

from ..models import Finding, Severity
from ..rules import custom_rules
from . import EntryContext, ToolError, run_tool

HIGH_NAMESPACES = ("collection/browser", "collection/credential", "credential-access", "persistence/",
                   "anti-analysis/anti-vm", "malware-family/", "collection/keylog", "impact/inhibit-system-recovery",
                   "impact/wipe-disk", "impact/ransom")
# Weaker signals (often just strings): worth a look, not a Review on their own.
MEDIUM_NAMESPACES = ("impact/", "anti-analysis/anti-forensic", "anti-analysis/obfuscation")
MEDIUM_NAMES = ("reference analysis tools strings", "reference anti-vm strings", "reference cryptocurrency strings")
HIGH_WORDS = ("credential", "password", "browser", "cookie", "keylog", "steal", "wallet", "persist",
              "vm detection", "detect vm", "sandbox", "debugger detection")
# capa's "reference ... strings" rules only look for words anywhere in the file. In games two classic misfires:
# the C runtime's weekday table ("Friday" matches /frida/), and a "Dash" move or ability (also a cryptocurrency).
# Matches inside data appended to the exe (compressed payloads, where random bytes spell "XENO" or "vBOx") are
# noise too. When nothing else is left the capability drops to Low, with the matched text shown.
BENIGN_STRINGS = {"friday", "dash"}
LIST_NAMESPACES = ("host-interaction/process/create", "communication/http", "communication/socket",
                   "anti-analysis/", "load-code/", "host-interaction/registry", "executable/installer")


PACKED_RE = re.compile(r"appears (to be )?packed|packed (sample|file|executable)|cannot handle packed", re.I)
LIMITED_RE = re.compile(r"not a valid PE file|unsupported (file|format|arch)|file limitation|appears (to be )?packed|"
                        r"\.NET sample|installer", re.I)


def capa_stderr_flags(stderr: str) -> tuple[bool, str]:
    """(appears packed, limitation message) from capa's log output.

    capa line-wraps its log and echoes file paths (which contain "unpacked/"), so collapse whitespace
    and match capa's own phrases rather than a bare "packed".
    """
    text = re.sub(r"\s+", " ", re.sub(r"\S+\.py:\d+", " ", stderr or ""))
    packed = bool(PACKED_RE.search(text))
    m = LIMITED_RE.search(text)
    limited = ""
    if m:
        limited = text[m.start():m.end() + 50].strip()[:120]
    return packed, limited


def _evidence(node: dict, out: list) -> None:
    """(matched text, file offsets) of the string/regex features that matched, walking capa's match tree."""
    if not isinstance(node, dict) or not node.get("success"):
        return
    feat = (node.get("node") or {}).get("feature") or {}
    if feat.get("type") in ("regex", "string", "substring"):
        offsets = lambda locs: [a.get("value") for a in locs or [] if isinstance(a, dict)  # noqa: E731
                                and a.get("type") == "file" and isinstance(a.get("value"), int)]
        if feat["type"] == "string" and not node.get("captures"):
            out.append((str(feat.get("string", "")), offsets(node.get("locations"))))
        for text, locs in (node.get("captures") or {}).items():
            out.append((str(text), offsets(locs)))
    for child in node.get("children") or []:
        _evidence(child, out)


def parse_capa(text: str) -> list[dict]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out = []
    for name, rule in (data.get("rules") or {}).items():
        meta = rule.get("meta", {})
        if meta.get("lib") or "internal" in (meta.get("namespace") or ""):
            continue
        attack = [a.get("technique", "") if isinstance(a, dict) else str(a) for a in meta.get("attack", []) or []]
        ev: list = []
        for m in rule.get("matches") or []:
            if isinstance(m, (list, tuple)) and len(m) == 2:
                _evidence(m[1], ev)
        out.append({"name": name, "namespace": meta.get("namespace") or "", "attack": attack, "evidence": ev})
    return out


def string_noise(cap: dict, overlay_offset: int | None) -> tuple[bool, str]:
    """For a "reference ... strings" rule: (only noise matched, the matched text for the report)."""
    if not cap["name"].lower().startswith("reference ") or not cap.get("evidence"):
        return False, ""
    real, shown = [], []
    for text, offs in cap["evidence"]:
        in_payload = bool(offs) and overlay_offset is not None and all(o >= overlay_offset for o in offs)
        harmless = text.strip().lower() in BENIGN_STRINGS
        shown.append(f"'{text[:24]}'" + (" (in appended data)" if in_payload else " (harmless word)" if harmless
                                           else ""))
        if not (in_payload or harmless):
            real.append(text)
    return not real, "matched " + ", ".join(shown[:6])


def is_high(cap: dict) -> bool:
    ns, name = cap["namespace"].lower(), cap["name"].lower()
    if name in MEDIUM_NAMES:
        return False
    return ns.startswith(HIGH_NAMESPACES) or any(w in name for w in HIGH_WORDS)


def is_medium(cap: dict) -> bool:
    ns, name = cap["namespace"].lower(), cap["name"].lower()
    return not is_high(cap) and (name in MEDIUM_NAMES or ns.startswith(MEDIUM_NAMESPACES))


# capa is the slowest, most memory-hungry tool. With parallel workers at most this many capa runs happen at
# once (pipeline sets it from [analysis] max_parallel_capa), so memory stays bounded.
_SLOTS = threading.BoundedSemaphore(2)


def set_parallel_capa(n: int) -> None:
    global _SLOTS
    _SLOTS = threading.BoundedSemaphore(max(1, int(n)))


def _cache_path(ctx: EntryContext, exe: str, sha256: str) -> "os.PathLike | None":
    """capa's raw output depends only on the file, the capa build and its rules, not on our code, so it is cached
    by file hash. A re-analysis after a code or rule change then re-grades the cached output in seconds."""
    if not sha256:
        return None
    try:
        st = os.stat(exe)
    except OSError:
        return None
    rules = str(ctx.cfg.section("tools").get("capa_rules") or "")
    key = hashlib.sha256(f"{exe}|{st.st_size}|{int(st.st_mtime)}|{rules}".encode()).hexdigest()[:16]
    return ctx.cfg.data_dir / "cache" / "capa" / f"{sha256}.{key}.json"


def _run_capa(ctx: EntryContext, exe: str, cmd: list[str], rec, timeout: int):
    """Returns (returncode, stdout, stderr), from the cache when this exact file was analysed before."""
    path = _cache_path(ctx, exe, rec.sha256)
    if path is not None and path.is_file():
        try:
            d = json.loads(path.read_text(encoding="utf-8"))
            return d["returncode"], d["stdout"], d["stderr"]
        except (OSError, ValueError, KeyError):
            pass
    with _SLOTS:
        p = run_tool(cmd, timeout=timeout)    # ToolError (timeout, memory) is not cached: a bigger limit retries
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(f".{threading.get_ident()}.tmp")
        tmp.write_text(json.dumps({"returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}),
                       encoding="utf-8")
        tmp.replace(path)
    return p.returncode, p.stdout, p.stderr


MAX_CAPA_FILES = 3
EXTRA_MAX_BYTES = 30 * 1024 * 1024   # extra (non-main) candidates only; capa on huge DLLs takes too long


def capa_candidates(ctx: EntryContext) -> list:
    """The main exe first, then other executables that aren't verified runtime files, largest first."""
    main = ctx.info.get("main_exe")
    rules = custom_rules(ctx.cfg.rules_dir)
    # A Godot executable is the stock engine with the game packed inside. GDRE recovers the game's scripts, which
    # the code rules check; capa on the 100+ MB engine itself needs over 8 GB of memory and adds little.
    godot_recovered = set((ctx.info.get("unwrapped") or {}).get("godot", []))
    out = []
    for r in ctx.files:
        if r.kind != "pe" or "vanished" in r.tags or "trusted-runtime" in r.tags or "electron-runtime" in r.tags:
            continue
        if r.path in godot_recovered:
            continue
        low = r.path.lower()
        if "/node_modules/" in low or not low.endswith((".exe", ".dll", ".scr", ".com", ".cpl", ".sys")):
            continue
        if r.path != main and (rules.is_helper_exe(low.rsplit("/", 1)[-1]) or r.size > EXTRA_MAX_BYTES):
            continue
        out.append(r)
    out.sort(key=lambda r: (r.path != main, r.origin == "unwrapped", not r.path.lower().endswith(".exe"), -r.size))
    return out[:MAX_CAPA_FILES]


def run(ctx: EntryContext) -> None:
    if not ctx.cfg.check_enabled("capa"):
        return
    exe = ctx.tool("capa")
    if not exe:
        ctx.not_run("capa", "capa not installed")
        return
    cands = capa_candidates(ctx)
    if not cands:
        engines = set(ctx.info.get("engines", []))
        godot = (ctx.info.get("unwrapped") or {}).get("godot")
        ctx.checks["capa"] = ("not run (Electron/NW.js runtime; app code inspected via unwrapping)"
                              if engines & {"electron", "nwjs"} else
                              "not run (Godot engine executable; game scripts recovered with GDRE and checked)"
                              if godot else "not run (no Windows executable to analyse)")
        return
    tools = ctx.cfg.section("tools")
    results, statuses = [], []
    for rec in cands:
        cmd = [exe, "-j"]
        if tools.get("capa_rules"):
            cmd += ["-r", str(tools["capa_rules"])]
        cmd.append(str(ctx.abspath(rec)))
        try:
            returncode, stdout, stderr = _run_capa(ctx, exe, cmd, rec, int(tools.get("capa_timeout", 900)))
        except ToolError as exc:
            if rec is cands[0]:
                ctx.error("capa", str(exc), rec.path)
                statuses.append("error")
            else:
                ctx.info.setdefault("notes", []).append(f"capa on {rec.path}: {exc}")
            continue
        packed, limited = capa_stderr_flags(stderr)
        if packed:
            ctx.add(Finding(rule="capa.packed", severity=Severity.MEDIUM, title="capa: executable appears packed",
                            file=rec.path, source="capa"))
        caps = parse_capa(stdout)
        if not caps and returncode != 0:
            if limited:
                statuses.append(f"limited ({limited})")
                continue
            ctx.error("capa", f"exit {returncode}: {(stderr or '').strip()[-200:]}", rec.path)
            statuses.append("error")
            continue
        overlay = ((ctx.info.get("pe") or {}).get(rec.path) or {}).get("overlay_offset")
        noise = {c["name"]: string_noise(c, overlay) for c in caps}
        for c in caps:
            only_noise, shown = noise[c["name"]]
            if only_noise and (is_high(c) or is_medium(c)):
                ctx.add(Finding(rule="capa.string_noise", severity=Severity.LOW, title=f"capa: {c['name']}",
                                file=rec.path, detail=f"{c['namespace']}; {shown}"[:300], source="capa"))
        caps = [c for c in caps if not noise[c["name"]][0]]
        high = [c for c in caps if is_high(c)]
        medium = [c for c in caps if is_medium(c)]
        listed = [c for c in caps if c not in high and c not in medium
                  and c["namespace"].lower().startswith(LIST_NAMESPACES)]
        results.append({"file": rec.path, "high": [c["name"] for c in high], "medium": [c["name"] for c in medium],
                        "notable": [c["name"] for c in listed][:25], "total": len(caps)})
        for c in medium:
            ctx.add(Finding(rule="capa.capability_weak", severity=Severity.MEDIUM, title=f"capa: {c['name']}",
                            file=rec.path, detail=(c["namespace"] + (f"; {noise[c['name']][1]}"
                                                                     if noise[c["name"]][1] else ""))[:300],
                            source="capa"))
        for c in high:
            ctx.add(Finding(rule="capa.capability", severity=Severity.HIGH, title=f"capa: {c['name']}",
                            file=rec.path,
                            detail=(c["namespace"] + (f" ({', '.join(c['attack'])})" if c["attack"] else "")
                                    + (f"; {noise[c['name']][1]}" if noise[c["name"]][1] else ""))[:300],
                            source="capa"))
        statuses.append("ok")
    if results:
        merged = dict(results[0])
        for extra in results[1:]:
            merged["high"] = merged["high"] + [h for h in extra["high"] if h not in merged["high"]]
            merged["notable"] = (merged["notable"] + extra["notable"])[:25]
        merged["files"] = [r["file"] for r in results]
        ctx.info["capa"] = merged
    if "ok" in statuses:
        ctx.checks["capa"] = "ok" if all(st == "ok" for st in statuses) else \
            f"ok ({statuses.count('ok')}/{len(statuses)} files)"
    elif any(st.startswith("limited") for st in statuses):
        ctx.checks["capa"] = next(st for st in statuses if st.startswith("limited"))
