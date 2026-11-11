"""Step 8: out/report.xlsx, out/report.html and out/manifest.csv from data/results/*.json.

The organiser's own columns (final verdict, notes, public-upload consent) are carried over
from an existing report.xlsx when the report is rebuilt.
"""
from __future__ import annotations

import csv
import json
import os
import re
import shutil
from pathlib import Path

from jinja2 import Environment, select_autoescape

from .config import Config
from .scoring import independent_sources
from .state import State, iso_now

COLUMNS = ["entry", "title", "author", "platforms", "has web build", "engine detected", "archive SHA-256",
           "main exe SHA-256", "VirusTotal", "MalwareBazaar", "AV", "YARA matches", "capa highlights",
           "flags", "independent sources", "suggested verdict", "final verdict", "public upload consent", "notes"]
USER_COLUMNS = ("final verdict", "public upload consent", "notes")
VERDICT_ORDER = {"Disqualify": 0, "Review": 1, "Sandbox OK": 2, "Web": 3}


def load_results(cfg: Config) -> list[dict]:
    out = []
    for p in sorted(cfg.results_dir.glob("*.json")):
        try:
            out.append(json.loads(p.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            continue
    for r in out:
        r["sources"] = sources_of(r)
    # Within a verdict, entries flagged by more independent sources come first.
    out.sort(key=lambda r: (VERDICT_ORDER.get(r.get("verdict"), 9), -len(r["sources"]), r.get("slug", "")))
    return out


class ReportUnreadable(Exception):
    """The existing report.xlsx exists but can't be read: never overwrite it (it holds the organiser's verdicts)."""


_ILLEGAL_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_CSV_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def _cell(v):
    """Make a value safe for a spreadsheet cell: no XML-illegal characters, within Excel's length limit."""
    if isinstance(v, str):
        v = _ILLEGAL_XML.sub("\ufffd", v)
        return v if len(v) <= 32000 else v[:32000] + "…"
    return v


def _csv_safe(v):
    """CSV cells starting with = + - @ are run as formulas when the file is opened in a spreadsheet."""
    s = str(v)
    return "'" + s if s.startswith(_CSV_FORMULA) else s


def read_user_columns(xlsx: Path, strict: bool = False) -> dict[str, dict[str, str]]:
    """{slug: {column: value}} for the organiser-maintained columns of an existing report.

    With strict=True an unreadable existing file raises ReportUnreadable instead of returning {}."""
    if not xlsx.is_file():
        return {}
    try:
        from openpyxl import load_workbook
        wb = load_workbook(xlsx, read_only=True, data_only=True)
    except Exception as exc:  # noqa: BLE001
        if strict:
            raise ReportUnreadable(f"{xlsx} could not be read ({type(exc).__name__}: {exc})") from exc
        return {}
    try:
        ws = wb["Entries"] if "Entries" in wb.sheetnames else wb.active
        rows = list(ws.iter_rows(values_only=True))
    finally:
        wb.close()
    if not rows:
        return {}
    header = [str(h or "").strip().lower() for h in rows[0]]
    if "entry" not in header:
        return {}
    idx = {c: header.index(c) for c in USER_COLUMNS if c in header}
    out = {}
    for row in rows[1:]:
        slug = row[header.index("entry")]
        if slug:
            out[str(slug)] = {c: ("" if row[i] is None else str(row[i])) for c, i in idx.items()}
    return out


def consent_for(cfg: Config, slug: str) -> bool:
    vals = read_user_columns(cfg.out_dir / "report.xlsx").get(slug, {})
    return vals.get("public upload consent", "").strip().lower() in ("y", "yes", "true", "1", "x", "ok")


def _main_and_archive(r: dict) -> tuple[str, str]:
    files = r.get("files", [])
    main = (r.get("info") or {}).get("main_exe", "")
    main_sha = next((f["sha256"] for f in files if f["path"] == main), "")
    archives = [f["sha256"] for f in files if f.get("origin") == "builds" and f.get("kind") == "archive"]
    return (" ".join(a for a in archives if a), main_sha)


def _lookup_state(r: dict, service: str) -> str:
    """'' when results are complete, otherwise why they aren't (not configured / pending / failed)."""
    services = r.get("lookup_services")
    if services is not None and service not in services:
        return "not configured"
    notes = []
    if (r.get("pending") or {}).get(service):
        notes.append(f"{len(r['pending'][service])} pending")
    if (r.get("lookup_errors") or {}).get(service):
        notes.append(f"{r['lookup_errors'][service]} failed")
    return ", ".join(notes)


def _vt_cell(r: dict, main: str) -> str:
    vt = (r.get("lookups") or {}).get("vt") or {}
    state = _lookup_state(r, "virustotal")
    if state == "not configured":
        return state
    suffix = f" ({state})" if state else ""
    if not vt:
        return state or "not found"
    flagged = {k: v for k, v in vt.items() if not v.startswith("0/")}
    if flagged:
        return "; ".join(f"{Path(k).name}: {v}" for k, v in list(flagged.items())[:4]) + suffix
    return f"0 detections on {len(vt)} known file(s)" + suffix


def _mb_cell(r: dict) -> str:
    mb = (r.get("lookups") or {}).get("mb") or {}
    state = _lookup_state(r, "malwarebazaar")
    text = "; ".join(f"{Path(k).name}: {v}" for k, v in mb.items())
    if state == "not configured":
        return text or state
    return (text or "not found") + (f" ({state})" if state else "")


def row_for(r: dict, user: dict[str, str]) -> dict[str, str]:
    info = r.get("info") or {}
    entry = r.get("entry") or {}
    arch, main = _main_and_archive(r)
    av = info.get("av") or {}
    flags = [f for f in r.get("findings", []) if f["severity"] in ("critical", "high", "medium", "low")]
    flag_text = "\n".join(f"[{f['severity'].upper()}] {f['title']}" + (f" ({f['file']})" if f.get("file") else "")
                          for f in flags[:25]) + (f"\n… +{len(flags) - 25} more" if len(flags) > 25 else "")
    checks = r.get("checks", {})
    av_text = "; ".join(f"{k}: {', '.join(v)}" for k, v in av.items()) or next(
        (f"{k}: {v}" for k, v in checks.items() if k in ("clamav", "defender") and v != "ok"), "not run")
    yara = info.get("yara") or {}
    capa = info.get("capa") or {}
    return {
        "entry": r.get("slug", ""),
        "title": entry.get("title", ""),
        "author": entry.get("author", ""),
        "platforms": ", ".join(entry.get("platforms") or []),
        "has web build": "yes" if r.get("has_web") else "no",
        "engine detected": info.get("engine", "unknown"),
        "archive SHA-256": arch,
        "main exe SHA-256": main,
        "VirusTotal": _vt_cell(r, main),
        "MalwareBazaar": _mb_cell(r),
        "AV": av_text,
        "YARA matches": "; ".join(sorted({m for ms in yara.values() for m in ms})) if yara else
                        ("not run" if str(checks.get("yara", "")).startswith("not run") else "none"),
        "capa highlights": ", ".join(capa.get("high", [])[:6] or capa.get("notable", [])[:6]) if capa else
                           str(checks.get("capa", "not run")),
        "flags": flag_text,
        "independent sources": _sources_text(r),
        "suggested verdict": r.get("verdict", "") + (" (provisional)" if r.get("provisional") else ""),
        "final verdict": user.get("final verdict", ""),
        "public upload consent": user.get("public upload consent", ""),
        "notes": user.get("notes", ""),
    }


def sources_of(r: dict) -> list[str]:
    """Independent sources that flagged this entry (recomputed for result files written before the field)."""
    return r.get("sources") if "sources" in r else independent_sources(r.get("findings") or [])


def _sources_text(r: dict) -> str:
    src = sources_of(r)
    return f"{len(src)}: {', '.join(src)}" if src else "0"


def write_xlsx(cfg: Config, results: list[dict], user: dict, path: Path) -> None:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.worksheet.datavalidation import DataValidation

    wb = Workbook()
    ws = wb.active
    ws.title = "Entries"
    ws.append(COLUMNS)
    fills = {"Disqualify": "F4B6B6", "Review": "F9E3A3", "Sandbox OK": "CDEBC5", "Web": "C9DDF2"}
    seen = set()
    for r in results:
        seen.add(r.get("slug", ""))
        row = row_for(r, user.get(r.get("slug", ""), {}))
        ws.append([_cell(row[c]) for c in COLUMNS])
        cell = ws.cell(row=ws.max_row, column=COLUMNS.index("suggested verdict") + 1)
        if r.get("verdict") in fills:
            cell.fill = PatternFill("solid", fgColor=fills[r["verdict"]])
    # Keep the organiser's notes for entries that are no longer in the results (renamed, removed, ...).
    for slug, vals in user.items():
        if slug not in seen and any(vals.values()):
            row = {c: "" for c in COLUMNS} | {"entry": slug, "suggested verdict": "(not in the current results)"} | vals
            ws.append([_cell(row[c]) for c in COLUMNS])
    for c in ws[1]:
        c.font = Font(bold=True)
    widths = {"flags": 70, "archive SHA-256": 22, "main exe SHA-256": 22, "notes": 40, "title": 28}
    for i, col in enumerate(COLUMNS, 1):
        ws.column_dimensions[ws.cell(row=1, column=i).column_letter].width = widths.get(col, 18)
    for row in ws.iter_rows(min_row=2):
        for c in row:
            c.alignment = Alignment(wrap_text=True, vertical="top")
    ws.freeze_panes = "B2"
    dv = DataValidation(type="list", formula1='"Disqualify,Review,Sandbox OK,Web"', allow_blank=True)
    ws.add_data_validation(dv)
    col = ws.cell(row=1, column=COLUMNS.index("final verdict") + 1).column_letter
    dv.add(f"{col}2:{col}{max(2, ws.max_row)}")

    fs = wb.create_sheet("Findings")
    fs.append(["entry", "severity", "rule", "title", "file", "line", "detail", "source"])
    for r in results:
        for f in r.get("findings", []):
            fs.append([_cell(x) for x in (r.get("slug"), f["severity"], f["rule"], f["title"], f.get("file", ""),
                                          f.get("line"), f.get("detail", ""), f.get("source", ""))])
    for c in fs[1]:
        c.font = Font(bold=True)
    # Text from submissions (titles, file names, details) must never become a live formula.
    for sheet in (ws, fs):
        for row in sheet.iter_rows(min_row=2):
            for c in row:
                if isinstance(c.value, str) and c.value.startswith("="):
                    c.data_type = "s"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.stem + ".tmp.xlsx")
    wb.save(tmp)
    if path.exists():
        shutil.copy2(path, path.with_name(path.stem + ".prev.xlsx"))   # one-step undo for the organiser
    try:
        os.replace(tmp, path)
    except PermissionError as exc:   # Windows: the report is open in Excel
        alt = path.with_name(path.stem + ".new.xlsx")
        os.replace(tmp, alt)
        raise ReportUnreadable(f"{path} is open in another program; the new report was saved as {alt}") from exc


def write_manifest(results: list[dict], path: Path) -> int:
    n = 0
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["entry", "file", "size", "sha256"])
        for r in results:
            for f in r.get("files", []):
                if f.get("origin") in ("builds", "unpacked") and f.get("sha256"):
                    w.writerow([_csv_safe(r.get("slug")), _csv_safe(f["path"]), f["size"], f["sha256"]])
                    n += 1
    return n


HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Jam triage report</title>
<style>
:root{--bg:#0b0f0b;--fg:#cfe8cf;--dim:#7c937c;--line:#1e2a1e;--crit:#ff5c5c;--high:#ffb347;--med:#e6d35a;--low:#8fd18f;--info:#7c937c;--card:#101710}
@media (prefers-color-scheme: light){:root{--bg:#f7faf7;--fg:#142014;--dim:#5b6e5b;--line:#d5e0d5;--card:#ffffff;--crit:#b3261e;--high:#b35c00;--med:#8a7a00;--low:#2e7d32;--info:#5b6e5b}}
body{background:var(--bg);color:var(--fg);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;margin:0;padding:16px}
h1,h2,h3{font-weight:600} h1{margin:.2em 0} a{color:inherit}
table{border-collapse:collapse;width:100%;margin:8px 0 24px} th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{color:var(--dim);font-weight:500} .wrap{overflow-x:auto}
.sev-critical{color:var(--crit);font-weight:700}.sev-high{color:var(--high);font-weight:700}.sev-medium{color:var(--med)}.sev-low{color:var(--low)}.sev-info{color:var(--info)}
.v{padding:1px 8px;border:1px solid currentColor;border-radius:3px;white-space:nowrap}
.v-Disqualify{color:var(--crit)}.v-Review{color:var(--high)}.v-Sandbox{color:var(--low)}.v-Web{color:#6fb3ff}
section.entry{background:var(--card);border:1px solid var(--line);padding:12px 16px;margin:16px 0}
code,.mono{word-break:break-all} .dim{color:var(--dim)} details summary{cursor:pointer;color:var(--dim)}
</style></head><body>
<h1>Jam triage report</h1>
<p class="dim">Generated {{ generated }} · platform {{ versions.platform or "?" }} · {{ results|length }} entries.
Suggested verdicts only: you make the final call. "Not found" means unknown, not clean.</p>
<h2>Summary</h2>
<div class="wrap"><table><tr><th>Entry</th><th>Engine</th><th>Web</th><th>Verdict</th><th>Sources</th><th>Top finding</th></tr>
{% for r in results %}<tr><td><a href="#e-{{ r.slug }}">{{ r.slug }}</a><br><span class="dim">{{ r.entry.title }} · {{ r.entry.author }}</span></td>
<td>{{ r.info.engine or "unknown" }}</td><td>{{ "yes" if r.has_web else "no" }}</td>
<td><span class="v v-{{ r.verdict.split()[0] }}">{{ r.verdict }}</span></td>
<td title="{{ r.sources|join(', ') }}">{{ r.sources|length }}</td>
<td>{% set t = r.findings[0] if r.findings else None %}{% if t and t.severity != "info" %}<span class="sev-{{ t.severity }}">[{{ t.severity|upper }}]</span> {{ t.title }}{% else %}<span class="dim">no flags</span>{% endif %}</td></tr>
{% endfor %}</table></div>
{% for r in results %}
<section class="entry" id="e-{{ r.slug }}">
<h3>{{ r.slug }} <span class="v v-{{ r.verdict.split()[0] }}">{{ r.verdict }}</span></h3>
<p class="dim">{{ r.entry.title }} by {{ r.entry.author or "?" }} {% if r.entry.url %}· <span class="mono">{{ r.entry.url }}</span>{% endif %}<br>
Engine: {{ r.info.engine or "unknown" }} · main exe: <span class="mono">{{ r.info.main_exe or "-" }}</span></p>
<p><b>Why this verdict:</b></p>
<p class="dim">Independent sources that flagged it (Medium or worse): {% if r.sources %}<b>{{ r.sources|length }}</b> · {{ r.sources|join(", ") }}{% else %}none{% endif %}</p>
{% if r.reasons %}<ul>{% for f in r.reasons %}<li><span class="sev-{{ f.severity }}">[{{ f.severity|upper }}]</span> {{ f.title }}{% if f.file %} <span class="dim mono">{{ f.file }}{% if f.line %}:{{ f.line }}{% endif %}</span>{% endif %}{% if f.detail %}<br><code class="dim">{{ f.detail }}</code>{% endif %}</li>{% endfor %}</ul>
{% else %}<p class="dim">No findings above Info.</p>{% endif %}
<details><summary>All findings ({{ r.findings|length }})</summary><div class="wrap"><table><tr><th>Severity</th><th>Finding</th><th>File</th><th>Detail</th><th>Source</th></tr>
{% for f in r.findings %}<tr><td class="sev-{{ f.severity }}">{{ f.severity }}</td><td>{{ f.title }}</td><td class="mono">{{ f.file }}{% if f.line %}:{{ f.line }}{% endif %}</td><td class="mono">{{ f.detail }}</td><td>{{ f.source }}</td></tr>{% endfor %}
</table></div></details>
<details><summary>Checks</summary><ul>{% for k, v in r.checks.items() %}<li>{{ k }}: {{ v }}</li>{% endfor %}</ul></details>
<details><summary>Files ({{ r.files|length }})</summary><div class="wrap"><table><tr><th>File</th><th>Kind</th><th>Size</th><th>SHA-256</th></tr>
{% for f in r.files[:400] %}<tr><td class="mono">{{ f.path }}</td><td>{{ f.kind }}</td><td>{{ f.size }}</td><td class="mono">{{ f.sha256 }}</td></tr>{% endfor %}
</table>{% if r.files|length > 400 %}<p class="dim">… {{ r.files|length - 400 }} more in manifest.csv</p>{% endif %}</div></details>
</section>
{% endfor %}
<h2>Tool and rule versions</h2>
<div class="wrap"><table><tr><th>Tool</th><th>Status</th><th>Version</th></tr>
{% for k, v in (versions.tools or {}).items() %}<tr><td>{{ k }}</td><td>{{ v.status }}</td><td class="mono">{{ v.version }}</td></tr>{% endfor %}
</table></div>
{% if versions.yara %}<p>YARA rule sets: {% for y in versions.yara %}<span class="mono">{{ y.file }} ({{ y.sha256 }}, {{ y.modified }})</span> {% endfor %}</p>{% endif %}
</body></html>"""


def write_html(results: list[dict], versions: dict, path: Path) -> None:
    env = Environment(autoescape=select_autoescape(default=True, default_for_string=True))
    html = env.from_string(HTML).render(results=results, versions=versions or {}, generated=iso_now())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")


def build_reports(cfg: Config) -> dict[str, Path]:
    cfg.ensure_dirs()
    results = load_results(cfg)
    xlsx = cfg.out_dir / "report.xlsx"
    state = State(cfg.state_db)
    versions = state.get_meta("versions", {})
    out = {"xlsx": xlsx, "html": cfg.out_dir / "report.html", "manifest": cfg.out_dir / "manifest.csv"}
    write_html(results, versions, out["html"])
    write_manifest(results, out["manifest"])
    try:
        user = read_user_columns(xlsx, strict=True)
    except ReportUnreadable:
        # Don't touch the organiser's file; write next to it instead.
        out["xlsx"] = xlsx.with_name("report.new.xlsx")
        write_xlsx(cfg, results, {}, out["xlsx"])
        out["warning"] = f"{xlsx.name} could not be read, so it was left untouched; new report: {out['xlsx'].name}"
        return out
    try:
        write_xlsx(cfg, results, user, xlsx)
    except ReportUnreadable as exc:
        out["xlsx"] = xlsx.with_name("report.new.xlsx")
        out["warning"] = str(exc)
    return out
