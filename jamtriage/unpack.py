"""Safe archive extraction.

Rules: read the member list first, refuse traversal, absolute paths, drive letters,
UNC paths and links, enforce limits on total size, file count, compression ratio and nesting depth,
and detect encrypted archives. Hitting a limit produces a finding, never a crash.

Nothing here executes extracted content, and extracted files never get execute permissions.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from .filetypes import archive_format
from .models import Finding, Severity
from .proc import run_group

CHUNK = 1024 * 1024
RATIO_MIN_BYTES = 1024 * 1024  # per-file ratio checks only apply to files of at least 1 MiB
_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}


@dataclass
class Limits:
    max_total_bytes: int = 4_000_000_000
    max_files: int = 20_000
    max_ratio: float = 100
    max_depth: int = 2

    @classmethod
    def from_config(cls, section: dict) -> "Limits":
        return cls(
            max_total_bytes=int(section.get("max_total_bytes", cls.max_total_bytes)),
            max_files=int(section.get("max_files", cls.max_files)),
            max_ratio=float(section.get("max_ratio", cls.max_ratio)),
            max_depth=int(section.get("max_depth", cls.max_depth)),
        )


@dataclass
class Budget:
    """Running totals for one entry, shared by all of its (nested) archives."""
    limits: Limits
    total_bytes: int = 0
    files: int = 0
    limit_hit: bool = False

    def bytes_left(self) -> int:
        return self.limits.max_total_bytes - self.total_bytes

    def files_left(self) -> int:
        return self.limits.max_files - self.files


@dataclass
class UnpackResult:
    findings: list[Finding] = field(default_factory=list)
    extracted: list[Path] = field(default_factory=list)  # absolute paths of extracted regular files
    encrypted: bool = False
    error: str | None = None


class LimitExceeded(Exception):
    pass


def safe_member_name(name: str) -> str | None:
    """Normalise an archive member name to a safe relative POSIX path, or None if it's unsafe."""
    if not name or "\x00" in name:
        return None
    n = name.replace("\\", "/")
    if n.startswith("/") or n.startswith("//") or _DRIVE_RE.match(n):
        return None
    parts = []
    for part in PurePosixPath(n).parts:
        if part in ("", "."):
            continue
        if part == "..":
            return None
        parts.append(part)
    if not parts:
        return None
    return "/".join(parts)


def _inside(base: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


MAX_COMPONENT_BYTES = 180
RUNNABLE_EXT = (".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".hta", ".lnk",
                ".msi", ".pif", ".cpl", ".jar", ".wsf", ".url", ".chm", ".reg", ".iso", ".img", ".vhd", ".vhdx")


def _short_component(part: str) -> str:
    """Shorten a path component that's too long for the filesystem, keeping its extension."""
    if len(part.encode("utf-8", "surrogateescape")) <= MAX_COMPONENT_BYTES:
        return part
    import hashlib
    stem, dot, ext = part.rpartition(".")
    if not dot or len(ext) > 10:
        stem, ext = part, ""
    digest = hashlib.sha256(part.encode("utf-8", "surrogateescape")).hexdigest()[:10]
    keep = stem.encode("utf-8", "surrogateescape")[:100].decode("utf-8", "ignore")
    return f"{keep}~{digest}" + (f".{ext}" if ext else "")


def _safe_target(dest: Path, rel: str) -> Path | None:
    parts = [_short_component(p) for p in rel.split("/")]
    # Windows can't create reserved device names; rename instead of failing.
    if os.name == "nt":
        parts = ["_" + p if p.split(".")[0].lower() in _RESERVED else p for p in parts]
    target = dest.joinpath(*parts)
    try:
        if not _inside(dest, target):
            return None
    except OSError:
        return None
    return target


def _free_target(target: Path) -> tuple[Path, bool]:
    """If target exists (duplicate or case-colliding name), pick name~2.ext etc. so both get scanned."""
    if not target.exists():
        return target, False
    n = 2
    while True:
        alt = target.with_name(f"{target.stem}~{n}{target.suffix}")
        if not alt.exists():
            return alt, True
        n += 1


def _was_extracted(dest: Path, rel: str, got: set[str]) -> bool:
    t = _safe_target(dest, rel)
    if t is None:
        return False
    exp = t.relative_to(dest).as_posix()
    stem = exp.rsplit(".", 1)[0]
    return exp in got or any(g.startswith(stem + "~") for g in got)


def _unextracted(result: UnpackResult, label: str, rel: str, why: str) -> None:
    """A member we could not extract is a member nobody scanned."""
    runnable = rel.lower().endswith(RUNNABLE_EXT)
    result.findings.append(Finding(
        rule="archive.unextracted", severity=Severity.HIGH,
        title="Archive member could not be extracted, so it was NOT scanned"
              + (" (executable or script)" if runnable else ""),
        file=f"{label}!{rel}", detail=why[:200], source="unpack"))


def _collisions(result: UnpackResult, label: str, names: list[str]) -> None:
    if names:
        result.findings.append(Finding(
            rule="archive.name_collision", severity=Severity.MEDIUM,
            title="Archive has duplicate or case-colliding names (which file a judge gets depends on the extractor)",
            file=label, detail=", ".join(repr(n) for n in names[:5]), source="unpack"))


def _blocked(result: UnpackResult, label: str, names: list[str], reason: str) -> None:
    if not names:
        return
    shown = ", ".join(repr(n) for n in names[:5]) + (f" (+{len(names) - 5} more)" if len(names) > 5 else "")
    result.findings.append(Finding(
        rule="archive.path_traversal" if reason == "traversal" else "archive.link_blocked",
        severity=Severity.MEDIUM,
        title=("Archive member tries to write outside its folder" if reason == "traversal"
               else "Archive contains links (not extracted)"),
        file=label, detail=f"blocked: {shown}", source="unpack"))


def _limit(result: UnpackResult, budget: Budget, label: str, what: str) -> None:
    """A limit stopped us from unpacking something: that content was NOT scanned, so a human must look."""
    budget.limit_hit = True
    result.findings.append(Finding(
        rule="archive.limit", severity=Severity.HIGH, title="Unpacking limit hit: some content was NOT scanned",
        file=label, detail=what, source="unpack"))


RATIO_EXTRACT_CAP = 1024 ** 3   # extract high-ratio archives anyway if they expand to at most 1 GiB


def _ratio_gate(result: UnpackResult, budget: Budget, label: str, declared: int, packed: int) -> bool:
    """True if extraction may go ahead. A high ratio alone (e.g. an exe padded with zeros to dodge scanners)
    is extracted and noted; only archives that would really blow the budget are refused (High)."""
    lim = budget.limits
    if declared < RATIO_MIN_BYTES or declared / max(1, packed) <= lim.max_ratio:
        return True
    ratio = declared / max(1, packed)
    if declared <= min(budget.bytes_left(), RATIO_EXTRACT_CAP):
        result.findings.append(Finding(
            rule="archive.high_ratio", severity=Severity.MEDIUM,
            title="Unusually high compression ratio (padding is a common scanner-evasion trick)",
            file=label, detail=f"{ratio:.0f}:1 ({declared} bytes from {packed}); extracted and scanned",
            source="unpack"))
        return True
    _limit(result, budget, label, f"compression ratio {ratio:.0f}:1 and {declared} bytes declared; "
                                  f"archive not extracted (zip bomb?)")
    return False


def _encrypted(result: UnpackResult, label: str, detail: str) -> None:
    result.encrypted = True
    result.findings.append(Finding(
        rule="archive.encrypted", severity=Severity.HIGH,
        title="Password-protected archive (rule break and scanner-evasion trick)",
        file=label, detail=detail, source="unpack"))


def _copy_limited(src, dst_path: Path, max_bytes: int) -> int:
    """Stream src to dst_path, refusing to write more than max_bytes. Returns bytes written."""
    written = 0
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    with open(dst_path, "wb") as out:
        while True:
            chunk = src.read(CHUNK)
            if not chunk:
                break
            written += len(chunk)
            if written > max_bytes:
                out.close()
                dst_path.unlink(missing_ok=True)
                raise LimitExceeded(f"member expanded beyond {max_bytes} bytes")
            out.write(chunk)
    os.chmod(dst_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
    return written


# --------------------------------------------------------------------------- zip

def zip_is_encrypted(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as zf:
            return any(i.flag_bits & 0x1 for i in zf.infolist())
    except Exception:  # noqa: BLE001  hostile zips can raise almost anything
        return False


def unpack_zip(archive: Path, dest: Path, budget: Budget, label: str) -> UnpackResult:
    result = UnpackResult()
    lim = budget.limits
    try:
        zf = zipfile.ZipFile(archive)
        zf.infolist()
    except Exception as exc:  # noqa: BLE001  (BadZipFile, UnicodeDecodeError on bad UTF-8 names, ...)
        if find_7z():
            return unpack_7z(archive, dest, budget, label)   # 7-Zip is more forgiving with damaged zips
        result.error = f"not a readable zip: {type(exc).__name__}: {exc}"
        return result
    with zf:
        infos = zf.infolist()
        enc = [i.filename for i in infos if i.flag_bits & 0x1]
        if enc:
            _encrypted(result, label, f"{len(enc)} encrypted member(s), e.g. {enc[0]!r}")

        traversal, links, todo = [], [], []
        for info in infos:
            mode = (info.external_attr >> 16) & 0o170000
            rel = safe_member_name(info.filename)
            if rel is None:
                traversal.append(info.filename)
            elif mode == stat.S_IFLNK:
                links.append(info.filename)
            elif not info.is_dir() and not (info.flag_bits & 0x1):
                todo.append((info, rel))
        _blocked(result, label, traversal, "traversal")
        _blocked(result, label, links, "link")

        declared = sum(i.file_size for i, _ in todo)
        packed = sum(i.compress_size for i, _ in todo) or 1
        if not _ratio_gate(result, budget, label, declared, packed):
            return result

        collided: list[str] = []
        unsupported: dict[str, str] = {}
        for info, rel in todo:
            if budget.files_left() <= 0:
                _limit(result, budget, label, f"file count limit {lim.max_files} reached")
                break
            if info.file_size > budget.bytes_left():
                _limit(result, budget, label, f"total size limit {lim.max_total_bytes} bytes reached at {rel!r}")
                break
            target = _safe_target(dest, rel)
            if target is None:
                _blocked(result, label, [info.filename], "traversal")
                continue
            target, clash = _free_target(target)
            if clash:
                collided.append(info.filename)
            try:
                with zf.open(info) as src:
                    # Never trust the header: cap at the declared size and the remaining budget.
                    written = _copy_limited(src, target, min(info.file_size, budget.bytes_left()))
            except LimitExceeded as exc:
                _limit(result, budget, label, f"{rel!r}: {exc}")
                continue
            except NotImplementedError as exc:
                target.unlink(missing_ok=True)
                unsupported[info.filename] = str(exc)
                continue
            except Exception as exc:  # noqa: BLE001  (BadZipFile, zlib.error, LZMAError, CRC errors, ...)
                target.unlink(missing_ok=True)
                _unextracted(result, label, rel, f"{type(exc).__name__}: {exc}")
                continue
            budget.total_bytes += written
            budget.files += 1
            result.extracted.append(target)
        _collisions(result, label, collided)
    if unsupported:
        # Compression methods Python can't read (Deflate64, PPMd, ...): let 7-Zip try those members.
        fallback = unpack_7z(archive, dest, budget, label, only=set(unsupported)) if find_7z() else None
        got = {p.relative_to(dest).as_posix() for p in (fallback.extracted if fallback else [])}
        if fallback:
            result.extracted.extend(fallback.extracted)
        for name, why in unsupported.items():
            rel = safe_member_name(name) or name
            if not _was_extracted(dest, rel, got):
                _unextracted(result, label, rel, why + ("" if fallback else " (install 7-Zip to extract it)"))
    return result


# --------------------------------------------------------------------------- tar

def unpack_tar(archive: Path, dest: Path, budget: Budget, label: str) -> UnpackResult:
    result = UnpackResult()
    lim = budget.limits
    try:
        tf = tarfile.open(archive, mode="r:*")
    except Exception as exc:  # noqa: BLE001
        result.error = f"not a readable tar: {exc}"
        return result
    with tf:
        traversal, links, todo = [], [], []
        declared = 0
        headers = 0
        try:
            for member in tf:
                headers += 1
                if headers > lim.max_files * 2:
                    _limit(result, budget, label, f"more than {lim.max_files * 2} entries in the listing")
                    break
                rel = safe_member_name(member.name)
                if rel is None:
                    traversal.append(member.name)
                elif member.issym() or member.islnk():
                    links.append(member.name)
                elif member.isfile():
                    todo.append((member, rel))
                    declared += member.size
                if len(todo) > lim.max_files or declared > lim.max_total_bytes:
                    break  # stop reading the listing; limits handled below
        except Exception as exc:  # noqa: BLE001
            result.error = f"tar listing failed: {type(exc).__name__}: {exc}"
        _blocked(result, label, traversal, "traversal")
        _blocked(result, label, links, "link")

        if not _ratio_gate(result, budget, label, declared, archive.stat().st_size):
            return result

        for member, rel in todo:
            if budget.files_left() <= 0:
                _limit(result, budget, label, f"file count limit {lim.max_files} reached")
                break
            if member.size > budget.bytes_left():
                _limit(result, budget, label, f"total size limit {lim.max_total_bytes} bytes reached at {rel!r}")
                break
            target = _safe_target(dest, rel)
            if target is None:
                continue
            target, _clash = _free_target(target)
            try:
                # filter="data" applies the stdlib's own safety checks on top of ours.
                safe_member = tarfile.data_filter(member, str(dest))
                src = tf.extractfile(safe_member)
                if src is None:
                    continue
                with src:
                    written = _copy_limited(src, target, min(member.size, budget.bytes_left()))
            except Exception as exc:  # noqa: BLE001
                _unextracted(result, label, rel, f"{type(exc).__name__}: {exc}")
                continue
            budget.total_bytes += written
            budget.files += 1
            result.extracted.append(target)
    return result


# --------------------------------------------------------------------------- 7z / rar via 7-Zip CLI

SEVEN_ZIP_OVERRIDE: str | None = None  # set from [tools.paths] 7z by the pipeline


def find_7z() -> str | None:
    if SEVEN_ZIP_OVERRIDE:
        return SEVEN_ZIP_OVERRIDE
    for name in ("7zz", "7z", "7za"):
        found = shutil.which(name)
        if found:
            return found
    return None


def parse_7z_slt(text: str) -> tuple[list[dict], bool]:
    """Parse `7z l -slt` output into member dicts. Returns (members, headers_encrypted)."""
    headers_encrypted = bool(re.search(r"wrong password|encrypted archive|can not open encrypted", text, re.I))
    members: list[dict] = []
    if "----------" not in text:
        return members, headers_encrypted
    body = text.split("----------", 1)[1]
    for block in re.split(r"\n\s*\n", body):
        item: dict = {}
        for line in block.strip().splitlines():
            key, sep, value = line.partition(" = ")
            if sep:
                item[key.strip()] = value.strip()
        if "Path" in item:
            members.append(item)
    return members, headers_encrypted


def unpack_7z(archive: Path, dest: Path, budget: Budget, label: str, timeout: int = 600,
              only: set[str] | None = None) -> UnpackResult:
    result = UnpackResult()
    exe = find_7z()
    if not exe:
        result.error = "7-Zip (7zz/7z) not installed; .7z/.rar not unpacked"
        return result
    try:
        proc = run_group([exe, "l", "-slt", "-pjamtriage-no-password", "--", str(archive)],
                              capture_output=True, text=True, timeout=120, errors="replace")
    except (subprocess.TimeoutExpired, OSError) as exc:
        result.error = f"7z listing failed: {exc}"
        return result
    members, hdr_enc = parse_7z_slt(proc.stdout + proc.stderr)
    if hdr_enc:
        _encrypted(result, label, "archive headers are encrypted")
        return result
    if not members and proc.returncode != 0:
        result.error = f"7-Zip could not read it: {(proc.stderr or proc.stdout).strip()[-200:]}"
        return result
    traversal, links, enc, todo = [], [], [], []
    for m in members:
        if m.get("Folder") == "+" or m.get("Attributes", "").startswith("D"):
            continue
        if only is not None and m["Path"] not in only and m["Path"].replace("\\", "/") not in only:
            continue
        rel = safe_member_name(m["Path"])
        attrs = m.get("Attributes", "")
        if rel is None:
            traversal.append(m["Path"])
        elif m.get("Symbolic Link") or re.search(r"\sl[rwx-]{9}", attrs):
            links.append(m["Path"])
        elif m.get("Encrypted") == "+":
            enc.append(m["Path"])
        else:
            todo.append((m, rel))
    if enc:
        _encrypted(result, label, f"{len(enc)} encrypted member(s), e.g. {enc[0]!r}")
    _blocked(result, label, traversal, "traversal")
    _blocked(result, label, links, "link")
    declared = sum(int(m.get("Size") or 0) for m, _ in todo if str(m.get("Size") or "0").isdigit())
    if not _ratio_gate(result, budget, label, declared, archive.stat().st_size):
        return result
    if declared > budget.bytes_left() or len(todo) > budget.files_left():
        _limit(result, budget, label, "archive exceeds remaining size/file budget; not extracted")
        return result
    if not todo:
        return result

    # Extract into a private staging dir, then validate every resulting path before moving it in.
    staging = dest.parent / (dest.name + ".staging")
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    listfile = staging.parent / (dest.name + ".members.txt")
    listfile.write_text("\n".join(m["Path"] for m, _ in todo), encoding="utf-8")
    failed: dict[str, str] = {}
    try:
        proc = run_group([exe, "x", "-y", "-pjamtriage-no-password", f"-o{staging}", "-scsUTF-8",
                               str(archive), f"@{listfile}"],
                              capture_output=True, text=True, timeout=timeout, errors="replace")
        # "ERROR: Data Error : Game.exe" / "ERROR: CRC Failed : x" -> that member's output is partial garbage.
        for line in (proc.stdout + "\n" + proc.stderr).splitlines():
            m = re.match(r"^\s*ERROR:\s*(.+?)\s*:\s*(.+?)\s*$", line)
            if m and safe_member_name(m.group(2)):
                failed[safe_member_name(m.group(2))] = m.group(1)
    except (subprocess.TimeoutExpired, OSError) as exc:
        result.error = f"7z extraction failed: {exc}"
    finally:
        listfile.unlink(missing_ok=True)
    for rel in failed:
        partial = staging.joinpath(*rel.split("/"))
        if partial.is_file() and not partial.is_symlink():
            partial.unlink()
    for root, dirs, files in os.walk(staging, followlinks=False):
        for name in dirs + files:
            p = Path(root) / name
            if p.is_symlink():
                p.unlink()
                links.append(str(p.relative_to(staging)))
        for name in files:
            p = Path(root) / name
            if not p.exists() or p.is_symlink():
                continue
            rel = p.relative_to(staging).as_posix()
            target = _safe_target(dest, rel)
            size = p.stat().st_size
            if target is None:
                continue
            if only is None:
                target, _clash = _free_target(target)
            elif target.exists():
                continue
            if size > budget.bytes_left() or budget.files_left() <= 0:
                _limit(result, budget, label, "size/file budget reached during extraction")
                break
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(p), str(target))
            os.chmod(target, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
            budget.total_bytes += size
            budget.files += 1
            result.extracted.append(target)
    shutil.rmtree(staging, ignore_errors=True)
    got = {p.relative_to(dest).as_posix() for p in result.extracted}
    missed = [rel for _m, rel in todo if not _was_extracted(dest, rel, got)]
    no_rar = (archive.suffix.lower() in (".rar", ".r00") or str(label).lower().endswith(".rar")) and any(
        "unsupported method" in failed.get(rel, "").lower() for rel in missed)
    if no_rar:
        # One root cause, one finding: this 7-Zip build has no RAR decoder (e.g. Homebrew's `sevenzip`).
        runnable = [r for r in missed if r.lower().endswith(RUNNABLE_EXT)]
        result.findings.append(Finding(
            rule="archive.unextracted", severity=Severity.HIGH,
            title=f"{len(missed)} RAR member(s) NOT extracted or scanned: this 7-Zip has no RAR decoder"
                  + (f" ({len(runnable)} executable or script)" if runnable else ""),
            file=label, detail=("install the official 7-Zip from 7-zip.org (it includes RAR) and set "
                                "[tools.paths] 7z; e.g. " + ", ".join(missed[:3]))[:300], source="unpack"))
    else:
        for rel in missed:
            _unextracted(result, label, rel, f"7-Zip: {failed.get(rel, 'member not produced')}")
    return result


# --------------------------------------------------------------------------- dispatcher

def unpack_gzip(archive: Path, dest: Path, budget: Budget, label: str) -> UnpackResult:
    """A single gzip/bz2/xz-compressed file (e.g. game.exe.gz)."""
    import bz2
    import gzip
    import lzma

    result = UnpackResult()
    name = archive.name
    for ext in (".gz", ".bz2", ".xz", ".gzip"):
        if name.lower().endswith(ext):
            name = name[: -len(ext)]
            break
    target = _safe_target(dest, _short_component(name or "decompressed"))
    opener = {"gzip": gzip.open, "bzip2": bz2.open, "xz": lzma.open}
    from .filetypes import magic_kind, read_head
    kind = magic_kind(read_head(archive, 16))
    try:
        cap = min(budget.bytes_left(), RATIO_EXTRACT_CAP, max(RATIO_MIN_BYTES,
                  int(archive.stat().st_size * budget.limits.max_ratio * 10)))
        with opener[kind](archive, "rb") as src:
            written = _copy_limited(src, target, cap)
    except LimitExceeded as exc:
        _limit(result, budget, label, f"decompressed size: {exc}")
        return result
    except Exception as exc:  # noqa: BLE001
        result.error = f"could not decompress: {type(exc).__name__}: {exc}"
        return result
    budget.total_bytes += written
    budget.files += 1
    result.extracted.append(target)
    return result


def unpack_archive(archive: Path, dest: Path, budget: Budget, label: str, fmt: str | None = None) -> UnpackResult:
    fmt = fmt or archive_format(archive)
    dest.mkdir(parents=True, exist_ok=True)
    if fmt == "gzip":
        return unpack_gzip(archive, dest, budget, label)
    if fmt == "zip":
        return unpack_zip(archive, dest, budget, label)
    if fmt == "tar":
        return unpack_tar(archive, dest, budget, label)
    if fmt in ("7z", "rar"):
        return unpack_7z(archive, dest, budget, label)
    return UnpackResult(error=f"unsupported archive format: {fmt}")


def unpack_recursive(archive: Path, dest: Path, budget: Budget, label: str, depth: int = 1,
                     fmt: str | None = None) -> UnpackResult:
    """Unpack an archive and any archives inside it, up to `max_depth` levels in total."""
    try:
        result = unpack_archive(archive, dest, budget, label, fmt)
    except Exception as exc:  # noqa: BLE001  keep whatever was written, flag the rest
        result = UnpackResult(error=f"{type(exc).__name__}: {exc}")
        if dest.exists():
            result.extracted = [p for p in dest.rglob("*") if p.is_file() and not p.is_symlink()]
    nested = [p for p in list(result.extracted) if archive_format(p)]
    for inner in nested:
        inner_label = f"{label}!{inner.relative_to(dest).as_posix()}"
        from .filetypes import PACKAGE_EXT
        is_package = inner.suffix.lower() in PACKAGE_EXT  # NW.js app, Java jar, Android apk: normal contents
        if not is_package:
            result.findings.append(Finding(
                rule="archive.nested", severity=Severity.MEDIUM, title="Archive inside the archive",
                file=inner_label, source="unpack"))
        if depth + 1 > budget.limits.max_depth:
            _limit(result, budget, inner_label, f"nesting depth limit {budget.limits.max_depth} reached; not unpacked")
            continue
        sub = unpack_recursive(inner, inner.parent / (inner.name + "__unpacked"), budget, inner_label, depth + 1)
        result.findings.extend(sub.findings)
        result.extracted.extend(sub.extracted)
        result.encrypted = result.encrypted or sub.encrypted
        if sub.error:
            result.findings.append(Finding(
                rule="archive.unreadable", severity=Severity.HIGH,
                title="Could not unpack nested archive: its contents were NOT scanned",
                file=inner_label, detail=sub.error, source="unpack"))
    return result
