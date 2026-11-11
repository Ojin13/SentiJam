"""Static checks on HTML5 builds. Files are read as text; nothing is ever opened in a browser."""
from __future__ import annotations

from ..models import Finding, Severity
from ..rules import web_rules
from . import EntryContext

WEB_EXEC_EXT = (".exe", ".dll", ".scr", ".bat", ".cmd", ".msi", ".apk", ".com", ".ps1", ".vbs", ".lnk")


def _external(domain: str | None, wr) -> bool:
    return bool(domain) and wr.domain_class(domain) != "itch"


def scan_web_file(text: str, kind: str, wr) -> list[tuple]:
    """Return [(rule, line, match, count)] for one file, one entry per rule."""
    hits: dict[str, list] = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 50000:
            line = line[:50000]
        for rule in wr.rules:
            if kind not in rule.applies:
                continue
            for m in rule.regex.finditer(line):
                if rule.external_only and not _external(m.groupdict().get("domain"), wr):
                    continue
                if rule.id in hits:
                    hits[rule.id][3] += 1
                else:
                    hits[rule.id] = [rule, lineno, m.group(0)[:160], 1]
                break
    return [tuple(v) for v in hits.values()]


def external_domains(text: str, wr) -> set[str]:
    out = set()
    for m in wr.external_code.finditer(text):
        d = next((g for g in m.groupdict().values() if g), None)
        if d:
            out.add(d.lower())
    return out


def run(ctx: EntryContext) -> None:
    if not ctx.cfg.check_enabled("web"):
        return
    roots = ctx.info.get("web_roots") or []
    if not roots:
        ctx.checks["web"] = "not run (no web build)"
        return
    wr = web_rules(ctx.cfg.rules_dir)
    loaders = ctx.info.setdefault("web_loaders", {})
    domains_seen: dict[str, str] = ctx.info.setdefault("web_domains", {})
    for root in roots:
        prefix = root + "/"
        for rec in [r for r in ctx.files if r.path.startswith(prefix)]:
            low = rec.path.lower()
            if rec.kind in ("pe", "elf", "macho") or low.endswith(WEB_EXEC_EXT):
                ctx.add(Finding(rule="web.executable_inside", severity=Severity.HIGH,
                                title="Executable inside a web build", file=rec.path, source="web"))
                continue
            if low.endswith((".html", ".htm")):
                kind = "html"
            elif low.endswith((".js", ".mjs")):
                kind = "js"
            else:
                continue
            is_index = low == (prefix + "index.html").lower()
            if (wr.is_loader(rec.path) or rec.size > wr.max_scan_bytes) and not is_index:
                loaders[rec.path] = rec.sha256
                continue
            try:
                text = ctx.abspath(rec).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for rule, line, match, count in scan_web_file(text, kind, wr):
                ctx.add(Finding(rule=f"web.{rule.id}", severity=rule.severity, title=f"Web build: {rule.title}",
                                file=rec.path, line=line,
                                detail=match + (f"  (+{count - 1} more)" if count > 1 else ""), source="web"))
            unknown, cdn = [], []
            for d in sorted(external_domains(text, wr)):
                cls = wr.domain_class(d)
                domains_seen[d] = cls
                if cls == "unknown":
                    unknown.append(d)
                elif cls == "cdn":
                    cdn.append(d)
            if unknown:
                ctx.add(Finding(rule="web.external_code", severity=Severity.MEDIUM,
                                title="Web build: loads code from an unknown outside domain", file=rec.path,
                                detail=", ".join(unknown), source="web"))
            if cdn:
                ctx.add(Finding(rule="web.external_cdn", severity=Severity.LOW,
                                title="Web build: loads code from a well-known CDN", file=rec.path,
                                detail=", ".join(cdn), source="web"))
    ctx.checks["web"] = "ok"
