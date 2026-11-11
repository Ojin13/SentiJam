"""PE inspection with pefile (imports, sections, packers, timestamps) and signify (Authenticode)."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from ..models import Finding, Severity
from ..rules import custom_rules
from . import EntryContext

PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".themida": "Themida", ".winlice": "WinLicense",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect", ".enigma1": "Enigma", ".enigma2": "Enigma",
    ".aspack": "ASPack", ".adata": "ASPack", ".mpress1": "MPRESS", ".mpress2": "MPRESS", "pec2": "PECompact",
    ".petite": "Petite", ".nsp0": "NsPack", ".nsp1": "NsPack", ".boom": "Boomerang",
}
# Imports that are worth listing in the report (Info) because stealers and loaders use them.
NOTABLE_IMPORTS = {"cryptunprotectdata", "urldownloadtofilea", "urldownloadtofilew", "internetopenurla",
                   "internetopenurlw", "winhttpopen", "shellexecutea", "shellexecutew", "createremotethread",
                   "writeprocessmemory", "virtualallocex", "setwindowshookexa", "setwindowshookexw",
                   "isdebuggerpresent", "checkremotedebuggerpresent", "regsetvalueexa", "regsetvalueexw"}


def inspect_pe(path, max_bytes: int) -> dict:
    import pefile

    info: dict = {"imports": [], "notable_imports": [], "sections": [], "packer": "", "signed": False}
    pe = pefile.PE(str(path), fast_load=True)
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                                               pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]])
        info["machine"] = hex(pe.FILE_HEADER.Machine)
        ts = pe.FILE_HEADER.TimeDateStamp
        info["timestamp"] = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d") if ts else ""
        info["is_dotnet"] = bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress)
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll = entry.dll.decode("latin-1", "replace") if entry.dll else ""
            for imp in entry.imports:
                if imp.name:
                    name = imp.name.decode("latin-1", "replace")
                    info["imports"].append(f"{dll}!{name}")
                    if name.lower() in NOTABLE_IMPORTS:
                        info["notable_imports"].append(f"{dll}!{name}")
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
            ent = s.get_entropy() if s.SizeOfRawData and s.SizeOfRawData < max_bytes else 0.0
            info["sections"].append({"name": name, "entropy": round(ent, 2), "raw": s.SizeOfRawData,
                                     "exec": bool(s.Characteristics & 0x20000000)})
            packer = PACKER_SECTIONS.get(name.lower())
            if packer:
                info["packer"] = packer
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        info["signed"] = bool(sec_dir.VirtualAddress and sec_dir.Size)
        info["cert_offset"], info["cert_size"] = int(sec_dir.VirtualAddress or 0), int(sec_dir.Size or 0)
        try:
            info["overlay_offset"] = pe.get_overlay_data_start_offset()
        except Exception:  # noqa: BLE001
            info["overlay_offset"] = None
    finally:
        pe.close()
    return info


_ORG_RE = re.compile(r"(?:^|,\s*)O=((?:\\,|[^,])+)")
_CORP_SUFFIX = {"corporation", "corp", "inc", "incorporated", "aps", "sf", "llc", "ltd", "limited", "gmbh", "sa",
                "s.a", "ab", "co", "oy", "pty", "plc", "bv", "b.v", "sp", "z", "o.o", "group", "kk", "ag", "foundation"}


def signer_org(signer_dn: str) -> str:
    m = _ORG_RE.search(signer_dn or "")
    return m.group(1).replace("\\,", ",").strip() if m else ""


def org_is_trusted(org: str, trusted: list[str]) -> bool:
    """Exact vendor name, optionally followed by corporate suffixes only ("Valve Corp." yes, "Valve Fans LLC" no)."""
    words = re.sub(r"[,()]", " ", org.lower()).split()
    for name in trusted:
        n = name.lower().split()
        if words[:len(n)] == n and all(w.rstrip(".") in _CORP_SUFFIX for w in words[len(n):]):
            return True
    return False


def runtime_is_trusted(ctx: EntryContext, rules, rec, status: str, signer: str) -> bool:
    # A valid (chain-verified) signature from a known engine/platform vendor: their file, whatever its name.
    if status == "ok" and org_is_trusted(signer_org(signer), rules.trusted_signers):
        return True
    if not rules.is_engine_runtime(rec.path):
        return False
    if rules.is_runtime_glob(rec.path):
        return True
    name = rec.path.rsplit("/", 1)[-1].lower()
    if name in rules.chromium_unsigned:
        folder = rec.path.rsplit("/", 1)[0]
        return any("electron-runtime" in r.tags and r.path.rsplit("/", 1)[0] == folder for r in ctx.files) or \
            any(r.path.rsplit("/", 1)[0] == folder and r.path.lower().endswith(("/nw.exe", "/nw.dll"))
                and r.size > 40 * 1024 * 1024 for r in ctx.files)
    return False


def verify_signature(path) -> tuple[str, str]:
    """Return (status, signer) where status is ok | invalid | unsigned | unknown."""
    try:
        from signify.authenticode import AuthenticodeVerificationResult
        from signify.authenticode.signed_file import SignedPEFile
    except ImportError:
        return "unknown", ""
    try:
        with open(path, "rb") as fh:
            spe = SignedPEFile(fh)
            signer = ""
            try:
                for sig in spe.signatures:
                    si = sig.signer_info
                    certs = list(sig.certificates.find_certificates(issuer=si.issuer, serial_number=si.serial_number))
                    if certs:
                        signer = certs[0].subject.dn
                    elif si.program_name:
                        signer = f"program name: {si.program_name}"
                    break
            except Exception:  # noqa: BLE001
                pass
            result, _err = spe.explain_verify()
            if result == AuthenticodeVerificationResult.OK:
                return "ok", signer
            if result == AuthenticodeVerificationResult.NOT_SIGNED:
                return "unsigned", ""
            return "invalid", f"{signer} ({result.name})".strip()
    except Exception as exc:  # noqa: BLE001
        return "unknown", str(exc)[:120]


def run(ctx: EntryContext, records=None) -> None:
    if not ctx.cfg.check_enabled("pe"):
        return
    if not ctx.tool("pefile"):
        ctx.not_run("pe", "pefile not installed")
        return
    rules = custom_rules(ctx.cfg.rules_dir)
    max_bytes = int(ctx.cfg.section("tools").get("max_scan_bytes", 256 << 20))
    results = ctx.info.setdefault("pe", {})
    sigs = ctx.info.setdefault("signatures", {})
    for rec in records if records is not None else ctx.records("pe"):
        if rec.kind != "pe" or "vanished" in rec.tags:
            continue
        p = ctx.abspath(rec)
        try:
            info = inspect_pe(p, max_bytes)
        except Exception as exc:  # noqa: BLE001  (pefile raises PEFormatError and others on hostile files)
            ctx.add(Finding(rule="pe.malformed", severity=Severity.LOW, title="Malformed PE file",
                            file=rec.path, detail=str(exc)[:200], source="pe"))
            continue
        status, signer = verify_signature(p) if info["signed"] else ("unsigned", "")
        runtime = runtime_is_trusted(ctx, rules, rec, status, signer)
        if runtime and "trusted-runtime" not in rec.tags:
            rec.tags.append("trusted-runtime")
        elif not runtime and "trusted-runtime" in rec.tags:
            rec.tags.remove("trusted-runtime")
        if rules.is_engine_runtime(rec.path) and not runtime and not rules.is_runtime_glob(rec.path):
            ctx.info.setdefault("notes", []).append(
                f"{rec.path.rsplit('/', 1)[-1]}: named like an engine runtime but not verifiably the vendor's; "
                f"scanned like any other file")
        results[rec.path] = {k: v for k, v in info.items() if k != "imports"}
        if any(i.lower().endswith("!cryptunprotectdata") for i in info["imports"]) and not runtime:
            ctx.add(Finding(rule="pe.cryptunprotectdata", severity=Severity.HIGH,
                            title="Imports CryptUnprotectData (decrypts saved browser passwords)",
                            file=rec.path, source="pe"))
        if info["packer"] and not runtime:
            rec.tags.append("packed")
            ctx.add(Finding(rule="pe.packed", severity=Severity.MEDIUM, title=f"Packed executable ({info['packer']})",
                            file=rec.path, detail="packer section names", source="pe"))
        elif not runtime and not info.get("is_dotnet"):
            execs = [s for s in info["sections"] if s["exec"] and s["raw"] > 64 * 1024]
            if execs and all(s["entropy"] > 7.4 for s in execs):
                rec.tags.append("packed")
                ctx.add(Finding(rule="pe.packed", severity=Severity.MEDIUM,
                                title="Executable code looks packed or encrypted (very high entropy)",
                                file=rec.path, detail=", ".join(f"{s['name']}={s['entropy']}" for s in execs),
                                source="pe"))
        if info["signed"]:
            sigs[rec.path] = {"status": status, "signer": signer}
            if status == "invalid" and not runtime:
                ctx.add(Finding(rule="pe.bad_signature", severity=Severity.MEDIUM,
                                title="Code signature present but invalid", file=rec.path, detail=signer,
                                source="pe"))
            elif status == "ok" and not runtime:
                ctx.add(Finding(rule="pe.signed", severity=Severity.INFO, title="Signed executable",
                                file=rec.path, detail=f"signer: {signer} (check it fits the author)", source="pe"))
        else:
            sigs[rec.path] = {"status": "unsigned", "signer": ""}
    ctx.checks["pe"] = "ok"
