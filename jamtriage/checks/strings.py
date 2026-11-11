"""Custom string rules (rules/custom.yaml) over executables, scripts and text files."""
from __future__ import annotations

import re
from pathlib import Path

from ..filetypes import CODE_EXT, is_string_scannable
from ..models import Finding
from ..rules import StringRule, custom_rules
from . import EntryContext, trusted_runtime

CHUNK = 4 * 1024 * 1024


def _variants(pattern: str) -> list[bytes]:
    low = pattern.lower()
    return [low.encode("latin-1", "ignore"), low.encode("utf-16-le", "ignore")]


def build_matcher(rules: list[StringRule]) -> tuple[re.Pattern, dict[bytes, tuple[StringRule, str]], int]:
    lookup: dict[bytes, tuple[StringRule, str]] = {}
    for rule in rules:
        for pat in rule.patterns:
            for v in _variants(pat):
                if v:
                    lookup.setdefault(v, (rule, pat))
    needles = sorted(lookup, key=len, reverse=True)
    rx = re.compile(b"|".join(re.escape(n) for n in needles)) if needles else re.compile(b"(?!x)x")
    return rx, lookup, max((len(n) for n in needles), default=1)


def scan_file(path: Path, rx: re.Pattern, lookup: dict, overlap: int, max_bytes: int) -> dict[str, tuple[StringRule, str, int]]:
    """Return {rule_id: (rule, pattern, offset)} for the first hit of each rule."""
    hits: dict[str, tuple[StringRule, str, int]] = {}
    pos, tail = 0, b""
    with open(path, "rb") as fh:
        while pos < max_bytes:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            buf = (tail + chunk).lower()
            base = pos - len(tail)
            for m in rx.finditer(buf):
                rule, pat = lookup[m.group(0)]
                if rule.id not in hits:
                    hits[rule.id] = (rule, pat, base + m.start())
            pos += len(chunk)
            tail = buf[-overlap:] if overlap else b""
    return hits


def _line_of(path: Path, offset: int) -> int | None:
    try:
        if path.stat().st_size > 8 * 1024 * 1024:
            return None
        data = path.read_bytes()[:offset]
        if b"\x00" in data[:4096]:
            return None
        return data.count(b"\n") + 1
    except OSError:
        return None


def run(ctx: EntryContext, records=None) -> None:
    if not ctx.cfg.check_enabled("strings"):
        return
    rules = custom_rules(ctx.cfg.rules_dir)
    rx, lookup, overlap = build_matcher(rules.string_rules)
    max_bytes = int(ctx.cfg.section("tools").get("max_scan_bytes", 256 << 20))
    for rec in records if records is not None else ctx.files:
        p = ctx.abspath(rec)
        if not is_string_scannable(rec.kind, p) or "vanished" in rec.tags:
            continue
        if trusted_runtime(rec) or "electron-runtime" in rec.tags:
            continue
        if rec.origin == "unwrapped" and p.suffix.lower() in CODE_EXT:
            continue  # recovered code is read by the per-language code rules instead
        try:
            hits = scan_file(p, rx, lookup, overlap, max_bytes)
        except OSError:
            continue
        for rule, pat, offset in hits.values():
            ctx.add(Finding(rule=f"strings.{rule.id}", severity=rule.severity, title=rule.title, file=rec.path,
                            detail=f"matched {pat!r} at offset {offset:#x}", source="strings",
                            line=_line_of(p, offset) if rec.kind in ("text", "script", "web") else None))
    ctx.checks["strings"] = "ok"
