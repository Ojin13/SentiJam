"""Step 7: turn findings (including hash lookup results) into a suggested verdict.

Disqualify : any Critical finding
Review     : any High finding, or 3+ Medium findings
Web        : the entry has a working web build (and nothing above)
Sandbox OK : only Low or Info findings
"""
from __future__ import annotations

import re

from .models import FileRecord, Finding, Severity

# Specific malware families (stealers, loaders, RATs, miners) that are common in fake-game campaigns.
SPECIFIC_FAMILY = re.compile(
    r"lumma|redline|vidar|raccoon|rhadamanthys|stealc|risepro|meta ?stealer|amadey|smoke ?loader|private ?loader|"
    r"asyncrat|njrat|remcos|quasar|darkgate|xworm|dcrat|nanocore|agent ?tesla|formbook|lokibot|azorult|mystic|"
    r"atomic ?stealer|\bamos\b|poseidon|banshee|cryptbot|blank ?grabber|empyrean|luna ?grabber|creal|"
    r"epsilon|pysilon|skuld|doenerium|exela|wave ?stealer|growtopia|xmrig|nitrogen|lummac|socks5systemz|"
    r"phemedrone|meduza|acr ?stealer|strela|venom ?rat|sectop|zgrat|purecrypter|pure ?logs|snake ?keylogger", re.I)
# Generic names that still mean "steals / spies / remote control", not just "looks odd".
GENERIC_BAD = re.compile(r"stealer|grabber|\bpws\b|psw|trojan.?spy|spyware|infostealer|\brat\b|backdoor|"
                         r"coin ?miner|\bminer\b|keylog|banker|token.?log", re.I)
# Machine-learning / heuristic verdicts: weakest evidence, frequent false positives on new indie builds.
ML_SUFFIX = re.compile(r"(!ml\b|\.ml\b|\bml\.|generic\.ml|aidetect|malicious_confidence|static ai|heuristic|"
                       r"susgen|deepscan|\(high confidence\)|^unsafe$|^malicious|score\b)", re.I)
NAMED_FAMILY = SPECIFIC_FAMILY   # backwards-compatible name

VERDICTS = ("Disqualify", "Review", "Web", "Sandbox OK")


def lookup_findings(records: list[FileRecord], cache_get, pending: dict[str, set[str]], engines: list[str],
                    signed: dict[str, dict]) -> tuple[list[Finding], dict]:
    """Findings from cached VirusTotal / MalwareBazaar / MetaDefender answers. Returns (findings, summary)."""
    out: list[Finding] = []
    summary: dict = {"vt": {}, "mb": {}, "md": {}}
    seen: set[str] = set()
    known_somewhere = False
    looked_up = 0
    game_engine = bool(set(engines) & {"godot", "unity", "unity-mono", "unity-il2cpp"})
    for rec in records:
        if not rec.sha256 or rec.sha256 in seen:
            continue
        seen.add(rec.sha256)
        cached = cache_get(rec.sha256) or {}
        mb, vt, md = cached.get("malwarebazaar"), cached.get("virustotal"), cached.get("metadefender")
        if mb or vt or md:
            looked_up += 1
        if mb and mb.get("found"):
            known_somewhere = True
            summary["mb"][rec.path] = mb.get("signature") or "known"
            out.append(Finding(rule="lookup.malwarebazaar", severity=Severity.CRITICAL,
                               title=f"MalwareBazaar knows this file: {mb.get('signature') or 'malware sample'}",
                               file=rec.path, detail=", ".join(mb.get("tags") or [])[:200], source="malwarebazaar"))
        if vt and vt.get("found"):
            known_somewhere = True
            mal = int(vt.get("malicious", 0))
            summary["vt"][rec.path] = f"{mal}/{vt.get('total', 0)}"
            dets = [(e, r or "") for e, r in vt.get("detections", [])]
            non_ml = [r for _, r in dets if not ML_SUFFIX.search(r)]
            consensus = " ".join([vt.get("label", ""), *vt.get("families", [])])   # VT's multi-engine label
            specific_engines = sum(1 for r in non_ml if SPECIFIC_FAMILY.search(r))
            detail = (vt.get("label") or ", ".join(f"{e}: {r}" for e, r in dets[:4]))[:240]
            critical = ((mal >= 3 and len(non_ml) >= 3) or mal >= 10
                        or (mal >= 2 and SPECIFIC_FAMILY.search(consensus))
                        or specific_engines >= 2)
            named = bool(SPECIFIC_FAMILY.search(" ".join(non_ml)) or GENERIC_BAD.search(" ".join(non_ml) + " " + consensus))
            if critical:
                out.append(Finding(rule="lookup.virustotal", severity=Severity.CRITICAL,
                                   title=f"VirusTotal: {mal}/{vt.get('total', 0)} engines flag this file",
                                   file=rec.path, detail=detail, source="virustotal"))
            elif named or mal >= 3:
                out.append(Finding(rule="lookup.virustotal_named", severity=Severity.HIGH,
                                   title=f"VirusTotal: {mal} engine(s) flag this file"
                                         + (" as a stealer/RAT/miner" if named else " (mostly generic/ML verdicts)"),
                                   file=rec.path, detail=detail, source="virustotal"))
            elif mal >= 1:
                unsigned = (signed.get(rec.path) or {}).get("status") != "ok"
                low = _all_ml(vt) and game_engine and unsigned
                out.append(Finding(rule="lookup.virustotal_weak",
                                   severity=Severity.LOW if low else Severity.MEDIUM,
                                   title=f"VirusTotal: {mal} engine(s) flag this file"
                                         + (" (generic ML hit, common false positive)" if low else ""),
                                   file=rec.path, detail=detail, source="virustotal"))
        # For a hash MetaDefender has never scanned it still answers 200, with one engine's cloud reputation
        # (total 1, no file data). That isn't "known": only count real multi-engine scans or a detection.
        if md and md.get("found") and (int(md.get("total") or 0) > 1 or int(md.get("detected") or 0) > 0):
            known_somewhere = True
            det = int(md.get("detected", 0))
            summary["md"][rec.path] = f"{det}/{md.get('total', 0)}"
            if det >= 3:
                out.append(Finding(rule="lookup.metadefender", severity=Severity.HIGH,
                                   title=f"MetaDefender: {det}/{md.get('total', 0)} engines flag this file",
                                   file=rec.path, detail=", ".join(md.get("threats", []))[:200], source="metadefender"))
            elif det:
                out.append(Finding(rule="lookup.metadefender_weak", severity=Severity.LOW,
                                   title=f"MetaDefender: {det} engine(s) flag this file", file=rec.path,
                                   detail=", ".join(md.get("threats", []))[:200], source="metadefender"))
    if looked_up and not known_somewhere:
        out.append(Finding(rule="lookup.unknown", severity=Severity.INFO,
                           title="Hash unknown everywhere (normal for a new jam game; unknown is not clean)",
                           detail=f"{looked_up} file(s) looked up", source="lookups"))
    if pending:
        for svc, hashes in pending.items():
            if hashes:
                out.append(Finding(rule="lookup.pending", severity=Severity.INFO,
                                   title=f"{svc}: {len(hashes)} lookup(s) still pending (finish with the next run)",
                                   source="lookups"))
    return out, summary


def _all_ml(vt: dict) -> bool:
    dets = vt.get("detections") or []
    return bool(dets) and all(ML_SUFFIX.search(r or "") for _, r in dets)


# File reputation: a file VirusTotal has known for over a year, scanned by 60+ engines with zero detections, is
# a widely distributed component (an installer plugin, a runtime helper), not something an entrant wrote last
# week. Our own heuristic findings on it drop to Low. Never touched: antivirus and lookup detections, sandbox
# results, "couldn't scan" findings, and anything Critical. A modified file has a new hash, so it can't borrow
# an old file's reputation.
REPUTATION_MIN_ENGINES = 60
REPUTATION_MIN_AGE_DAYS = 365
HEURISTIC_SOURCES = {"strings", "code", "pe", "capa", "yara", "engine", "web"}


def established_clean(vt: dict | None, today=None) -> str:
    """First-seen date if VirusTotal's report shows an old, widely scanned, never-detected file; else ""."""
    from datetime import date
    if not vt or not vt.get("found"):
        return ""
    if int(vt.get("malicious") or 0) or int(vt.get("suspicious") or 0):
        return ""
    if int(vt.get("total") or 0) < REPUTATION_MIN_ENGINES:
        return ""
    try:
        first = date.fromisoformat(str(vt.get("first_seen") or "")[:10])
    except ValueError:
        return ""
    return first.isoformat() if ((today or date.today()) - first).days >= REPUTATION_MIN_AGE_DAYS else ""


def apply_reputation(findings: list[Finding], records: list[FileRecord], cache_get, today=None) -> list[Finding]:
    """Lower our heuristic findings on files with an established clean reputation (see above)."""
    known = {}
    for rec in records:
        if rec.sha256:
            since = established_clean((cache_get(rec.sha256) or {}).get("virustotal"), today)
            if since:
                known[rec.path] = since
    if not known:
        return findings
    out = []
    for f in findings:
        since = known.get(f.file)
        if since and f.source in HEURISTIC_SOURCES and Severity.MEDIUM <= f.severity < Severity.CRITICAL:
            f = Finding(rule=f.rule, severity=Severity.LOW, title=f.title, file=f.file, source=f.source,
                        line=f.line, detail=(f"[lowered from {f.severity.label}: known clean on VirusTotal since "
                                             f"{since}] " + f.detail)[:400])
        out.append(f)
    return out


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        k = (f.rule, f.file, f.line, f.detail)
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def verdict(findings: list[Finding], has_web: bool) -> tuple[str, list[Finding]]:
    """Return (verdict, the findings that caused it)."""
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    if crit:
        return "Disqualify", crit
    high = [f for f in findings if f.severity == Severity.HIGH]
    med = [f for f in findings if f.severity == Severity.MEDIUM]
    if high or len(med) >= 3:
        return "Review", high + (med if len(med) >= 3 else [])
    if has_web:
        return "Web", [f for f in findings if f.severity >= Severity.LOW]
    return "Sandbox OK", [f for f in findings if f.severity >= Severity.LOW]


# Corroboration: how many INDEPENDENT detection sources flagged an entry (Medium or worse). Several checks
# of our own (strings, code, PE, engine, web, unwrap, DiE) share one rule author, so they count as one
# source; each external vendor, database and sandbox counts separately. Findings about coverage
# ("couldn't unpack", "lookup pending", "analysis failed") say nothing about malware and don't count.
# It's shown next to the verdict; the verdict itself still follows the severity rules above.
SOURCE_GROUPS = {
    "clamav": "ClamAV", "defender": "Microsoft Defender", "mdatp": "Microsoft Defender",
    "yara": "YARA rules", "capa": "capa",
    "strings": "jam-triage rules", "code": "jam-triage rules", "pe": "jam-triage rules",
    "engine": "jam-triage rules", "web": "jam-triage rules", "unwrap": "jam-triage rules",
    "diec": "jam-triage rules",
    "virustotal": "VirusTotal engines", "malwarebazaar": "MalwareBazaar", "metadefender": "MetaDefender",
    "virustotal-sandbox": "VirusTotal sandbox", "virustotal-behaviour": "VirusTotal sandbox",
    "hybrid-sandbox": "Hybrid Analysis sandbox", "hybrid-analysis": "Hybrid Analysis sandbox",
}
COVERAGE_RULES = {"analysis.error", "archive.unextracted", "archive.unreadable", "pe.installer_unscanned",
                  "unwrap.failed", "unwrap.not_inspectable", "detonation.no_report"}


def independent_sources(findings: list) -> list[str]:
    """Names of the independent sources with a Medium-or-worse finding (accepts Findings or their dicts)."""
    out = set()
    for f in findings:
        rule, source, sev = ((f.rule, f.source, f.severity) if isinstance(f, Finding)
                             else (f.get("rule", ""), f.get("source", ""), f.get("severity", "info")))
        try:
            if Severity.parse(sev) < Severity.MEDIUM:
                continue
        except (KeyError, ValueError):
            continue
        if rule == "av.vanished":                   # the local antivirus removed the file while we read it
            out.add("local antivirus")
        elif rule not in COVERAGE_RULES and source in SOURCE_GROUPS:
            out.add(SOURCE_GROUPS[source])
    return sorted(out)


def counts(findings: list[Finding]) -> dict[str, int]:
    c = {s.label: 0 for s in Severity}
    c["errors"] = 0
    for f in findings:
        c[f.severity.label] += 1
        if f.rule == "analysis.error":
            c["errors"] += 1
    return c
