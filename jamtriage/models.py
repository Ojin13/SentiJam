"""Shared data types: severities, findings and file records."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | "Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).strip().upper()]

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass
class Finding:
    rule: str                 # stable id, e.g. "archive.encrypted", "strings.discord-webhook"
    severity: Severity
    title: str                # one line, human readable
    file: str = ""            # path relative to the entry (or archive!member)
    detail: str = ""          # evidence: matched text, engine names, tool output excerpt
    source: str = ""          # check that produced it: inventory, unpack, clamav, yara, ...
    line: int | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.label
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(
            rule=d["rule"],
            severity=Severity.parse(d["severity"]),
            title=d.get("title", ""),
            file=d.get("file", ""),
            detail=d.get("detail", ""),
            source=d.get("source", ""),
            line=d.get("line"),
        )

    def key(self) -> tuple:
        return (self.rule, self.file, self.line, self.detail)


@dataclass
class FileRecord:
    path: str                 # relative to the entry root, prefixed by area: builds/, unpacked/, unwrapped/
    size: int
    kind: str                 # archive, pe, elf, macho, script, web, text, data, image, audio, other
    sha256: str = ""
    sha1: str = ""
    md5: str = ""
    origin: str = "builds"    # builds | unpacked | unwrapped
    archive: str = ""         # which archive it came from (for unpacked files)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "FileRecord":
        return cls(**{k: d[k] for k in cls.__dataclass_fields__ if k in d})
