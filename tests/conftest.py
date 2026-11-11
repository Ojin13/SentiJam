from __future__ import annotations

import copy
from pathlib import Path

import pytest

from jamtriage.config import DEFAULTS, Config

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    raw = copy.deepcopy(DEFAULTS)
    raw["paths"] = {"data": str(tmp_path / "data"), "out": str(tmp_path / "out"), "rules": str(ROOT / "rules")}
    for svc in ("virustotal", "malwarebazaar", "metadefender"):
        raw[svc]["enabled"] = False
    raw["antivirus"]["update_before_scan"] = False
    raw["antivirus"]["enabled"] = False   # keep unit tests fast and independent of installed AV
    c = Config(root=ROOT, raw=raw, platform="macos")
    c.ensure_dirs()
    return c
