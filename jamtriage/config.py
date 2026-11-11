"""Configuration loading: defaults, then config.toml, then config.local.toml (personal, git-ignored);
API keys come from the environment / .env."""
from __future__ import annotations

import copy
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULTS: dict = {
    "paths": {"data": "data", "out": "out", "rules": "rules"},
    "virustotal": {"enabled": True, "requests_per_minute": 4, "daily_budget": 480, "monthly_budget": 15000,
                   "max_lookups_per_entry": 12},
    "malwarebazaar": {"enabled": True, "requests_per_minute": 20, "daily_budget": 2000, "max_lookups_per_entry": 40},
    "metadefender": {"enabled": False, "requests_per_minute": 10, "daily_budget": 900, "max_lookups_per_entry": 12},
    "unpack": {"max_total_bytes": 4_000_000_000, "max_files": 20_000, "max_ratio": 100, "max_depth": 2},
    "antivirus": {"enabled": True, "update_before_scan": True, "timeout_seconds": 1800},
    "tools": {
        "diec_timeout": 120,
        "capa_timeout": 900,
        "max_tool_memory_mb": 8192,
        "capa_rules": "",
        "extractor_timeout": 600,
        "yara_timeout": 60,
        "max_scan_bytes": 256 * 1024 * 1024,
        "paths": {},
    },
    "analysis": {"workers": 3, "max_parallel_capa": 2},
    "sandbox": {"consent_all": False, "min_age_minutes": 30},   # sandboxes only run when a command asks
    "detonation": {"timeout_seconds": 300},
    "hybridanalysis": {"requests_per_minute": 60, "daily_submissions": 95, "daily_requests": 5000,
                       "environment_id": 160, "upload": "exe", "max_upload_mb": 100},
    "dashboard": {"host": "127.0.0.1", "port": 8787, "refresh_seconds": 2},
}

ENV_KEYS = ("ITCH_API_KEY", "VT_API_KEY", "MB_AUTH_KEY", "MD_API_KEY", "HA_API_KEY")


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def load_dotenv(path: Path) -> None:
    """Minimal .env reader: KEY=VALUE lines; never overrides variables already set."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().removeprefix("export ").strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


@dataclass
class Config:
    root: Path
    raw: dict
    platform: str = "linux"
    selftest: bool = False
    # Optional filter used by the self-test: only these SHA-256s may be looked up online.
    lookup_allowlist: set[str] | None = None
    only: set[str] = field(default_factory=set)

    def section(self, name: str) -> dict:
        return self.raw.get(name, {})

    @property
    def data_dir(self) -> Path:
        return self._path("data")

    @property
    def out_dir(self) -> Path:
        return self._path("out")

    @property
    def rules_dir(self) -> Path:
        return self._path("rules")

    def _path(self, key: str) -> Path:
        p = Path(self.raw["paths"][key])
        return p if p.is_absolute() else (self.root / p)

    @property
    def builds_dir(self) -> Path:
        return self.data_dir / "builds"

    @property
    def unpacked_dir(self) -> Path:
        return self.data_dir / "unpacked"

    @property
    def unwrapped_dir(self) -> Path:
        return self.data_dir / "unwrapped"

    @property
    def results_dir(self) -> Path:
        return self.data_dir / "results"

    @property
    def cache_file(self) -> Path:
        return self.data_dir / "cache" / "lookups.json"

    @property
    def state_db(self) -> Path:
        return self.data_dir / "state.db"

    @staticmethod
    def key(name: str) -> str | None:
        value = os.environ.get(name, "").strip()
        return value or None

    def check_enabled(self, name: str) -> bool:
        """`--only` restricts which local checks run; empty means all."""
        return not self.only or name in self.only

    def tool_paths(self) -> dict[str, str]:
        """[tools.paths] overrides: check key -> executable path (relative paths are relative to config.toml)."""
        out = {}
        for key, value in (self.section("tools").get("paths") or {}).items():
            if value:
                p = Path(str(value)).expanduser()
                out[key] = str(p if p.is_absolute() else self.root / p)
        return out

    def ensure_dirs(self) -> None:
        for d in (self.builds_dir, self.unpacked_dir, self.unwrapped_dir, self.results_dir,
                  self.cache_file.parent, self.out_dir):
            d.mkdir(parents=True, exist_ok=True)


def load_config(path: Path | None = None, *, root: Path | None = None, overrides: dict | None = None) -> Config:
    root = Path(root or (path.parent if path else Path.cwd())).resolve()
    cfg_path = path or (root / "config.toml")
    raw = copy.deepcopy(DEFAULTS)
    # config.local.toml next to config.toml holds personal settings (tool paths, consent) and is not committed.
    for p in (cfg_path, cfg_path.with_name("config.local.toml")):
        if p.is_file():
            with open(p, "rb") as fh:
                raw = _merge(raw, tomllib.load(fh))
    if overrides:
        raw = _merge(raw, overrides)
    load_dotenv(root / ".env")
    return Config(root=root, raw=raw)
