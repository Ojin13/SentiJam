"""Discover entries under data/builds/.

Supported layouts:
  * itch-dl:  builds/<author>/<game>/{metadata.json, files/...}
  * manual:   builds/<entry>/<any files>          (for paid or restricted entries downloaded by hand)
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+")
ITCH_DL_SIDE_FILES = {"metadata.json", "site.html", "game.json"}
ITCH_DL_SIDE_DIRS = {"screenshots"}


def slugify(text: str) -> str:
    s = _SLUG_RE.sub("-", text).strip("-.")
    return s[:120] or "entry"


@dataclass
class Entry:
    slug: str
    root: Path                       # entry folder under builds/
    metadata: dict = field(default_factory=dict)

    @property
    def title(self) -> str:
        v = self.metadata.get("title")
        return str(v) if v else self.slug

    @property
    def author(self) -> str:
        v = self.metadata.get("author")
        return str(v) if v else ""

    @property
    def url(self) -> str:
        v = self.metadata.get("url")
        return str(v) if v else ""

    @property
    def platforms(self) -> list[str]:
        extra = self.metadata.get("extra")
        extra = extra if isinstance(extra, dict) else {}
        plats = extra.get("platforms")
        if isinstance(plats, dict):
            return list(plats.keys())
        if isinstance(plats, list):
            return [str(p) for p in plats]
        return []

    @property
    def claimed_engine(self) -> str:
        extra = self.metadata.get("extra")
        extra = extra if isinstance(extra, dict) else {}
        made = extra.get("made_with")
        if isinstance(made, dict):
            return ", ".join(made.keys())
        if isinstance(made, (list, tuple)):
            return ", ".join(str(m) for m in made)
        return str(made or "")

    def build_files(self) -> list[Path]:
        """Every downloaded file of the entry, excluding itch-dl side files (page, cover, screenshots)."""
        files_dir = self.root / "files"
        if files_dir.is_dir() and (self.root / "metadata.json").exists():
            base = files_dir
            out = [p for p in base.rglob("*") if p.is_file() and not p.is_symlink()]
        else:
            out = []
            itch_dl = (self.root / "metadata.json").exists()   # only skip side files for real itch-dl folders
            for p in self.root.rglob("*"):
                if not p.is_file() or p.is_symlink():
                    continue
                rel = p.relative_to(self.root)
                if itch_dl and (rel.parts[0] in ITCH_DL_SIDE_DIRS
                                or (len(rel.parts) == 1 and p.name in ITCH_DL_SIDE_FILES)):
                    continue
                out.append(p)
        return sorted(out)


def _load_meta(d: Path) -> dict:
    meta = d / "metadata.json"
    if meta.is_file():
        try:
            data = json.loads(meta.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError, RecursionError):
            return {}
        return data if isinstance(data, dict) else {}
    return {}


def _is_entry_dir(d: Path) -> bool:
    return (d / "metadata.json").is_file() or (d / "files").is_dir()


def discover_entries(builds: Path) -> list[Entry]:
    entries: list[Entry] = []
    if not builds.is_dir():
        return entries
    seen: set[str] = set()

    def add(slug: str, d: Path) -> None:
        base, n = slugify(slug), 2
        s = base
        while s in seen:
            s, n = f"{base}-{n}", n + 1
        seen.add(s)
        entries.append(Entry(slug=s, root=d, metadata=_load_meta(d)))

    for d in sorted(p for p in builds.iterdir() if p.is_dir() and not p.name.startswith(".")):
        if _is_entry_dir(d):
            add(d.name, d)
            continue
        subs = [s for s in sorted(d.iterdir()) if s.is_dir() and _is_entry_dir(s)]
        if subs:  # itch-dl author folder
            for s in subs:
                add(f"{d.name}--{s.name}", s)
        else:     # manual layout: the folder itself is the entry
            add(d.name, d)
    return entries
