"""Streaming file hashes (SHA-256, SHA-1, MD5)."""
from __future__ import annotations

import hashlib
from pathlib import Path

CHUNK = 1024 * 1024


def hash_file(path: Path) -> dict[str, str]:
    sha256, sha1, md5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
    return {"sha256": sha256.hexdigest(), "sha1": sha1.hexdigest(), "md5": md5.hexdigest()}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()
