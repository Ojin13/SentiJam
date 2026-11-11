"""Per-language rules (rules/code.yaml) over recovered game code and loose source files."""
from __future__ import annotations

import re
import sys

from ..filetypes import CODE_EXT
from ..models import Finding
from ..rules import CodeRule, code_rules, web_rules
from . import EntryContext

MAX_CODE_BYTES = 20 * 1024 * 1024
_PRINTABLE = re.compile(rb"[\x20-\x7e]{3,}")
_PYI_BOOT = re.compile(r"^(pyimod\d*|pyiboot\d*|pyi_rth_.*|struct|pyi_.*)\.pyc$", re.IGNORECASE)


def _pyc_strings(data: bytes) -> str:
    return "\n".join(m.group(0).decode("ascii") for m in _PRINTABLE.finditer(data))


def _pyinstaller_scope(rel: str) -> str | None:
    """Return 'skip', 'third' or None (full severity) for files from a PyInstaller extraction."""
    parts = rel.split("/")
    name = parts[-1]
    if _PYI_BOOT.match(name):
        return "skip"
    pyz = next((i for i, p in enumerate(parts) if p.lower().startswith("pyz") and p.lower().endswith("_extracted")), None)
    if pyz is None:
        return None
    top = parts[pyz + 1].split(".")[0] if len(parts) > pyz + 1 else ""
    if top in sys.stdlib_module_names or top.startswith("_"):
        return "skip"
    return "third"


def scan_text(text: str, rules: list[CodeRule], use_pyc: bool = False) -> dict[str, tuple[CodeRule, int, str, int]]:
    """Return {rule_id: (rule, first_line, match_text, count)}."""
    hits: dict[str, tuple[CodeRule, int, str, int]] = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 20000:
            line = line[:20000]
        for rule in rules:
            rx = rule.pyc_regex if (use_pyc and rule.pyc_regex is not None) else rule.regex
            m = rx.search(line)
            if not m:
                continue
            if rule.id in hits:
                r, ln, txt, cnt = hits[rule.id]
                hits[rule.id] = (r, ln, txt, cnt + 1)
            else:
                hits[rule.id] = (rule, lineno, m.group(0)[:160], 1)
    return hits


def run(ctx: EntryContext, records=None) -> None:
    if not ctx.cfg.check_enabled("code"):
        return
    cr = code_rules(ctx.cfg.rules_dir)
    wr = web_rules(ctx.cfg.rules_dir)
    scanned = 0
    for rec in records if records is not None else ctx.files:
        p = ctx.abspath(rec)
        lang = CODE_EXT.get(p.suffix.lower())
        if not lang or "vanished" in rec.tags or rec.size > MAX_CODE_BYTES:
            continue
        low = rec.path.lower()
        if lang == "javascript" and wr.is_loader(rec.path):
            continue  # engine loader / minified library: hashed, not read line by line
        third = cr.is_third_party(rec.path)
        is_pyc = p.suffix.lower() == ".pyc"
        if rec.origin == "unwrapped" and "/pyinstaller/" in low:
            scope = _pyinstaller_scope(rec.path)
            if scope == "skip":
                continue
            third = third or scope == "third"
        try:
            data = p.read_bytes()
        except OSError:
            continue
        text = _pyc_strings(data) if is_pyc else data.decode("utf-8", "replace")
        lang_rules = cr.languages.get(lang, [])
        hits = scan_text(text, lang_rules + cr.shared, use_pyc=is_pyc)
        scanned += 1
        for rule, line, match, count in hits.values():
            sev = rule.severity
            capped = third and rule.noisy and not rule.shared and sev > cr.third_party_max
            if capped:
                sev = cr.third_party_max
            prefix = "shared" if rule.shared else lang
            ctx.add(Finding(rule=f"code.{prefix}.{rule.id}", severity=sev,
                            title=rule.title + (" (third-party code)" if third and not rule.shared else ""),
                            file=rec.path, line=None if is_pyc else line,
                            detail=f"{match}" + (f"  (+{count - 1} more)" if count > 1 else ""), source="code"))
    ctx.info["code_files_scanned"] = scanned
    ctx.checks["code"] = "ok"
