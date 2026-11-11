"""File classification by magic bytes and extension. Reads only the first bytes of a file."""
from __future__ import annotations

import re
from pathlib import Path

EXECUTABLE_EXT = {".exe", ".dll", ".scr", ".com", ".sys", ".cpl", ".ocx", ".so", ".dylib", ".x86_64", ".x86"}
# Script / shortcut / "opens something" types that Windows acts on when double-clicked (flagged High).
DANGEROUS_SCRIPT_EXT = {".scr", ".lnk", ".hta", ".vbs", ".vbe", ".ps1", ".psm1", ".js", ".jse", ".wsf", ".wsh", ".pif",
                        ".url", ".website", ".chm", ".scf", ".reg", ".inf", ".application", ".appref-ms",
                        ".settingcontent-ms", ".iqy", ".slk", ".xll", ".wsc", ".sct", ".msc", ".cpl", ".gadget",
                        ".library-ms", ".search-ms", ".diagcab", ".msp", ".mst", ".xbap", ".jnlp"}
SCRIPT_EXT = {".bat", ".cmd", ".py", ".pyw", ".sh", ".command", ".jar"} | DANGEROUS_SCRIPT_EXT
DISK_IMAGE_EXT = {".iso", ".img", ".vhd", ".vhdx", ".udf"}
# Containers 7-Zip can open: their contents get the same checks as any other archive.
SEVEN_ZIP_CONTAINER_EXT = DISK_IMAGE_EXT | {".dmg", ".cab", ".msi", ".ntfs", ".fat", ".hfs", ".apfs", ".wim", ".xar",
                                            ".cpio", ".rpm", ".deb", ".arj", ".lzh", ".lha", ".zst"}
# Zip-based packages that are normal inside a build (not "archive inside the archive").
PACKAGE_EXT = {".nw", ".jar", ".apk", ".aab", ".ipa", ".love", ".xpi", ".crx", ".nupkg", ".appx", ".msix"}
LAUNCHER_EXT = {".bat", ".cmd"}
INSTALLER_EXT = {".msi", ".msix", ".appx", ".msixbundle"}
ARCHIVE_EXT = {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz"} | PACKAGE_EXT
WEB_EXT = {".html", ".htm", ".js", ".mjs", ".wasm", ".css"}
CODE_EXT = {".gd": "gdscript", ".cs": "csharp", ".js": "javascript", ".mjs": "javascript",
            ".cjs": "javascript", ".ts": "javascript", ".jse": "javascript",
            ".py": "python", ".pyc": "python", ".pyw": "python", ".rpy": "python",   # Ren'Py scripts embed Python
            ".bat": "batch", ".cmd": "batch", ".ps1": "powershell", ".psm1": "powershell",
            ".vbs": "vbscript", ".vba": "vbscript", ".wsf": "vbscript", ".hta": "vbscript", ".wsc": "vbscript",
            ".sct": "vbscript", ".sh": "shell", ".command": "shell", ".bash": "shell", ".zsh": "shell",
            ".applescript": "shell", ".lua": "lua"}
MAC_EXT = {".dmg", ".pkg", ".app"}
MOBILE_EXT = {".apk", ".aab", ".ipa"}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".tga", ".psd", ".svg", ".ktx", ".dds"}
AUDIO_EXT = {".ogg", ".wav", ".mp3", ".flac", ".bank", ".wem", ".bnk", ".opus", ".m4a", ".mid"}
VIDEO_EXT = {".mp4", ".webm", ".mov", ".avi", ".mkv"}
# Big engine data packs: hashed, AV/YARA scanned, but not string-scanned.
ENGINE_DATA_EXT = {".pck", ".assets", ".ress", ".resource", ".bundle", ".pak", ".data", ".unity3d",
                   ".rpa", ".rpyc", ".win", ".ucas", ".utoc", ".sharedassets", ".mem", ".symbols"}
TEXT_EXT = {".txt", ".md", ".json", ".cfg", ".ini", ".xml", ".yaml", ".yml", ".toml", ".csv", ".log",
            ".tscn", ".tres", ".gd", ".cs", ".py", ".lua", ".rpy", ".godot", ".desktop", ".plist"}

DECOY_EXT = ("png", "jpg", "jpeg", "gif", "txt", "pdf", "doc", "docx", "mp4", "mp3", "zip", "rar", "html", "xlsx")
RUN_EXT = ("exe", "scr", "bat", "cmd", "com", "pif", "lnk", "js", "vbs", "hta", "msi", "ps1", "jar", "wsf")
DOUBLE_EXT_RE = re.compile(r"\.(%s)\.(%s)$" % ("|".join(DECOY_EXT), "|".join(RUN_EXT)), re.IGNORECASE)
RTLO = "‮"


def read_head(path: Path, n: int = 512) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(n)
    except OSError:
        return b""


def magic_kind(head: bytes) -> str | None:
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macho"
    if head[:4] == b"\xca\xfe\xba\xbe" and len(head) >= 8 and int.from_bytes(head[4:8], "big") < 40:
        return "macho"  # fat binary (Java class files share the magic but have a large version number)
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if head[:6] == b"Rar!\x1a\x07":
        return "rar"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if head[:3] == b"BZh":
        return "bzip2"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"  # .msi, old Office documents
    if head[:4] == b"\x4c\x00\x00\x00":
        return "lnk"
    return None


def has_zip_tail(path: Path) -> bool:
    """A zip end-of-central-directory record near the end: a zip with junk (or a stub) in front of it."""
    try:
        size = path.stat().st_size
        if size < 22:
            return False
        with open(path, "rb") as fh:
            fh.seek(max(0, size - 65557))
            return b"PK\x05\x06" in fh.read()
    except OSError:
        return False


def archive_format(path: Path, head: bytes | None = None) -> str | None:
    """Return zip/tar/7z/rar if this file should be unpacked, else None."""
    head = head if head is not None else read_head(path, 512)
    mk = magic_kind(head)
    name = path.name.lower()
    if mk == "zip":
        return "zip"   # includes .jar/.apk/.nw/.love packages: their contents get scanned too
    if mk == "7z":
        return "7z"
    if mk == "rar":
        return "rar"
    if mk == "tar" or name.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")):
        return "tar"
    if mk in ("gzip", "bzip2", "xz"):
        return "tar" if ".tar" in name else "gzip"   # single compressed file, e.g. game.exe.gz
    if path.suffix.lower() in SEVEN_ZIP_CONTAINER_EXT or mk == "ole" and name.endswith((".msi", ".msp")):
        return "7z"
    if mk is None and (path.suffix.lower() in (".zip", ".zipx", ".love", ".nw", ".jar", ".apk", "")) \
            and has_zip_tail(path):
        return "zip"   # junk-prefixed zip (executables with appended zips are handled by the unwrap step)
    return None


def classify(path: Path, head: bytes | None = None) -> tuple[str, list[str]]:
    """Return (kind, tags) for a file on disk."""
    head = head if head is not None else read_head(path, 512)
    ext = path.suffix.lower()
    name = path.name
    tags: list[str] = []
    mk = magic_kind(head)

    if DOUBLE_EXT_RE.search(name):
        tags.append("double-extension")
    if RTLO in name:
        tags.append("rtlo-filename")
    if ext in DANGEROUS_SCRIPT_EXT:
        tags.append("dangerous-script")
    if ext in LAUNCHER_EXT:
        tags.append("launcher-script")
    if ext in INSTALLER_EXT or (mk == "ole" and ext in (".msi", "")):
        tags.append("installer")
    if ext in DISK_IMAGE_EXT:
        tags.append("disk-image")
    if ext in MAC_EXT or mk == "macho":
        tags.append("macos")
    if ext in MOBILE_EXT:
        tags.append("mobile")
    if ext in CODE_EXT:
        tags.append("code:" + CODE_EXT[ext])

    fmt = archive_format(path, head)
    if fmt:
        return "archive", tags + ["archive:" + fmt]
    if mk == "pe":
        if ext not in EXECUTABLE_EXT:
            tags.append("pe-disguised" if ext and ext not in (".bin", ".node", ".pyd", ".mui") else "pe")
        return "pe", tags
    if mk == "elf":
        return "elf", tags
    if mk == "macho":
        return "macho", tags
    if mk == "lnk" or ext == ".lnk":
        return "script", tags
    if ext in (".com", ".exe", ".scr", ".pif", ".cpl"):
        # Windows-executable name without a PE header: a DOS .com program (they have no header at all),
        # or something disguised. Either way it must be looked up and AV-scanned like an executable.
        tags.append("executable-no-pe")
        return "other", tags
    if ext in SCRIPT_EXT:
        return ("web" if ext in (".js",) else "script"), tags
    if ext in WEB_EXT:
        return "web", tags
    if ext in IMAGE_EXT:
        return "image", tags
    if ext in AUDIO_EXT or ext in VIDEO_EXT:
        return "audio", tags
    if ext in ENGINE_DATA_EXT:
        return "data", tags
    if ext in TEXT_EXT:
        return "text", tags
    if ext in INSTALLER_EXT or mk == "ole":
        return "installer", tags
    if ext in MAC_EXT:
        return "macos", tags
    return "other", tags


def is_lookup_worthy(kind: str, tags: list[str]) -> bool:
    """Files worth an online hash lookup: executables, scripts, installers, archives, odd files."""
    if kind in ("pe", "elf", "macho", "script", "installer", "archive", "macos"):
        return True
    return any(t in tags for t in ("double-extension", "rtlo-filename", "pe-disguised", "dangerous-script",
                                   "executable-no-pe"))


def is_string_scannable(kind: str, path: Path) -> bool:
    if kind in ("image", "audio", "data"):
        return False
    return path.suffix.lower() not in ENGINE_DATA_EXT
