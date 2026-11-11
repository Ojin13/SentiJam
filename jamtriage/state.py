"""Persistent state: SQLite (progress, lookup queue, quota counters, log) and the JSON lookup cache."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    slug TEXT PRIMARY KEY, title TEXT, status TEXT DEFAULT 'queued', stage TEXT DEFAULT '',
    verdict TEXT DEFAULT '', top_severity TEXT DEFAULT '', top_finding TEXT DEFAULT '',
    counts TEXT DEFAULT '{}', updated REAL
);
CREATE TABLE IF NOT EXISTS lookups (
    service TEXT, sha256 TEXT, tier INTEGER, status TEXT DEFAULT 'pending', attempts INTEGER DEFAULT 0,
    error TEXT DEFAULT '', entries TEXT DEFAULT '[]', created REAL, updated REAL,
    PRIMARY KEY (service, sha256)
);
CREATE INDEX IF NOT EXISTS lookups_queue ON lookups (service, status, tier, created);
CREATE TABLE IF NOT EXISTS quota (service TEXT, day TEXT, used INTEGER DEFAULT 0, PRIMARY KEY (service, day));
CREATE TABLE IF NOT EXISTS limiter (service TEXT PRIMARY KEY, last_request REAL DEFAULT 0, paused_until REAL DEFAULT 0);
CREATE TABLE IF NOT EXISTS log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, entry TEXT, message TEXT);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS sandbox (
    slug TEXT PRIMARY KEY, file TEXT, sha256 TEXT, status TEXT, uploaded REAL DEFAULT 0, ref TEXT DEFAULT '',
    checked REAL DEFAULT 0, attempts INTEGER DEFAULT 0, note TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sandbox_runs (
    provider TEXT, slug TEXT, file TEXT, sha256 TEXT, status TEXT, uploaded REAL DEFAULT 0, ref TEXT DEFAULT '',
    checked REAL DEFAULT 0, attempts INTEGER DEFAULT 0, note TEXT DEFAULT '', PRIMARY KEY (provider, slug)
);
INSERT OR IGNORE INTO sandbox_runs (provider, slug, file, sha256, status, uploaded, ref, checked, attempts, note)
    SELECT 'virustotal', slug, file, sha256, status, uploaded, ref, checked, attempts, note FROM sandbox;
"""


def utc_day(ts: float | None = None) -> str:
    return datetime.fromtimestamp(time.time() if ts is None else ts, tz=timezone.utc).strftime("%Y-%m-%d")


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class State:
    """Thin wrapper around state.db; one connection per thread, WAL mode."""

    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self.conn.executescript(SCHEMA)

    @property
    def conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=30, isolation_level=None, check_same_thread=False)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA busy_timeout=30000")
            self._local.conn = c
        return c

    # ---------------------------------------------------------------- meta / log
    def set_meta(self, key: str, value) -> None:
        self.conn.execute("INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                          (key, json.dumps(value)))

    def get_meta(self, key: str, default=None):
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row["value"]) if row else default

    def log(self, message: str, entry: str = "") -> None:
        self.conn.execute("INSERT INTO log(ts, entry, message) VALUES(?, ?, ?)", (time.time(), entry, message))

    def recent_log(self, n: int = 20) -> list[dict]:
        rows = self.conn.execute("SELECT ts, entry, message FROM log ORDER BY id DESC LIMIT ?", (n,)).fetchall()
        return [dict(r) for r in reversed(rows)]

    # ---------------------------------------------------------------- entries
    def upsert_entry(self, slug: str, **fields) -> None:
        fields["updated"] = time.time()
        if "counts" in fields and not isinstance(fields["counts"], str):
            fields["counts"] = json.dumps(fields["counts"])
        cols = ", ".join(["slug", *fields])
        qs = ", ".join("?" * (len(fields) + 1))
        upd = ", ".join(f"{k}=excluded.{k}" for k in fields)
        self.conn.execute(f"INSERT INTO entries({cols}) VALUES({qs}) ON CONFLICT(slug) DO UPDATE SET {upd}",
                          (slug, *fields.values()))

    def entries(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM entries ORDER BY slug").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["counts"] = json.loads(d.get("counts") or "{}")
            out.append(d)
        return out

    # ---------------------------------------------------------------- lookup queue
    def enqueue_lookup(self, service: str, sha256: str, tier: int, entry: str) -> None:
        now = time.time()
        row = self.conn.execute("SELECT tier, entries FROM lookups WHERE service=? AND sha256=?",
                                (service, sha256)).fetchone()
        if row is None:
            self.conn.execute("INSERT INTO lookups(service, sha256, tier, entries, created, updated) VALUES(?,?,?,?,?,?)",
                              (service, sha256, tier, json.dumps([entry]), now, now))
            return
        ents = json.loads(row["entries"] or "[]")
        if entry not in ents:
            ents.append(entry)
        # A lookup that failed earlier (network trouble, server error) gets another chance on a later run.
        self.conn.execute("UPDATE lookups SET tier=MIN(tier, ?), entries=?, updated=?, "
                          "status=CASE WHEN status='error' AND attempts < 6 THEN 'pending' ELSE status END "
                          "WHERE service=? AND sha256=?",
                          (tier, json.dumps(ents), now, service, sha256))

    def next_lookup(self, service: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM lookups WHERE service=? AND status='pending' ORDER BY tier, created LIMIT 1",
            (service,)).fetchone()

    def finish_lookup(self, service: str, sha256: str, status: str, error: str = "") -> None:
        self.conn.execute("UPDATE lookups SET status=?, error=?, attempts=attempts+1, updated=? WHERE service=? AND sha256=?",
                          (status, error[:500], time.time(), service, sha256))

    def requeue_all(self, service: str | None = None) -> int:
        q = "UPDATE lookups SET status='pending' WHERE status IN ('done','error')"
        args: tuple = ()
        if service:
            q += " AND service=?"
            args = (service,)
        return self.conn.execute(q, args).rowcount

    def pending_count(self, service: str) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM lookups WHERE service=? AND status='pending'",
                                 (service,)).fetchone()[0]

    def lookup_status(self, service: str, sha256: str) -> str | None:
        row = self.conn.execute("SELECT status FROM lookups WHERE service=? AND sha256=?", (service, sha256)).fetchone()
        return row["status"] if row else None

    # ---------------------------------------------------------------- quota / limiter
    def quota_used(self, service: str, day: str | None = None) -> int:
        row = self.conn.execute("SELECT used FROM quota WHERE service=? AND day=?",
                                (service, day or utc_day())).fetchone()
        return row["used"] if row else 0

    def quota_add(self, service: str, n: int = 1, day: str | None = None) -> None:
        self.conn.execute("INSERT INTO quota(service, day, used) VALUES(?,?,?) "
                          "ON CONFLICT(service, day) DO UPDATE SET used=used+excluded.used",
                          (service, day or utc_day(), n))

    def quota_used_month(self, service: str, day: str | None = None) -> int:
        month = (day or utc_day())[:7]
        row = self.conn.execute("SELECT COALESCE(SUM(used), 0) AS n FROM quota WHERE service=? AND day LIKE ?",
                                (service, month + "-%")).fetchone()
        return int(row["n"])

    def take_slot(self, service: str, interval: float, now: float, daily_budget: int | None,
                  monthly_budget: int | None) -> tuple[str, float]:
        """Atomically decide whether one request may be sent now, and if so record it.

        Returns ("ok", 0), ("wait", seconds), ("paused", seconds), ("daily", 0) or ("monthly", 0).
        BEGIN IMMEDIATE takes SQLite's write lock, so two threads or two processes sharing state.db
        can never both get the same slot or both spend the last unit of budget.
        """
        c = self.conn
        c.execute("BEGIN IMMEDIATE")
        try:
            day = utc_day(now)
            if daily_budget is not None and self.quota_used(service, day) >= daily_budget:
                c.execute("COMMIT")
                return "daily", 0.0
            if monthly_budget is not None and self.quota_used_month(service, day) >= monthly_budget:
                c.execute("COMMIT")
                return "monthly", 0.0
            last, paused = self.limiter_get(service)
            wait = max(paused - now, last + interval - now)
            if wait > 0:
                c.execute("COMMIT")
                return ("paused" if paused > now else "wait"), wait
            self.limiter_set(service, last_request=now)
            self.quota_add(service, 1, day)
            c.execute("COMMIT")
            return "ok", 0.0
        except BaseException:
            c.execute("ROLLBACK")
            raise

    # ---------------------------------------------------------------- VirusTotal sandbox batch
    # One row per (sandbox provider, entry): "virustotal" or "hybrid".
    def sandbox_get(self, slug: str, provider: str = "virustotal") -> dict | None:
        row = self.conn.execute("SELECT * FROM sandbox_runs WHERE provider=? AND slug=?", (provider, slug)).fetchone()
        return dict(row) if row else None

    def sandbox_set(self, slug: str, provider: str = "virustotal", **fields) -> None:
        cur = self.sandbox_get(slug, provider) or {"provider": provider, "slug": slug, "file": "", "sha256": "",
                                                   "status": "", "uploaded": 0, "ref": "", "checked": 0,
                                                   "attempts": 0, "note": ""}
        cur.update(fields)
        cols = list(cur)
        self.conn.execute(f"INSERT OR REPLACE INTO sandbox_runs({','.join(cols)}) "
                          f"VALUES({','.join('?' * len(cols))})", [cur[c] for c in cols])

    def sandbox_all(self, provider: str = "virustotal") -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM sandbox_runs WHERE provider=? ORDER BY slug",
                                                   (provider,))]

    def limiter_get(self, service: str) -> tuple[float, float]:
        row = self.conn.execute("SELECT last_request, paused_until FROM limiter WHERE service=?", (service,)).fetchone()
        return (row["last_request"], row["paused_until"]) if row else (0.0, 0.0)

    def limiter_set(self, service: str, last_request: float | None = None, paused_until: float | None = None) -> None:
        lr, pu = self.limiter_get(service)
        self.conn.execute("INSERT INTO limiter(service, last_request, paused_until) VALUES(?,?,?) "
                          "ON CONFLICT(service) DO UPDATE SET last_request=excluded.last_request, "
                          "paused_until=excluded.paused_until",
                          (service, lr if last_request is None else last_request,
                           pu if paused_until is None else paused_until))


class LookupCache:
    """data/cache/lookups.json: {sha256: {service: {..., "ts": iso}}}. Thread-safe, atomic writes."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._data: dict = {}
        if path.is_file():
            try:
                self._data = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._data = {}

    def get(self, sha256: str, service: str) -> dict | None:
        with self._lock:
            return self._data.get(sha256, {}).get(service)

    def all_for(self, sha256: str) -> dict:
        with self._lock:
            return dict(self._data.get(sha256, {}))

    def put(self, sha256: str, service: str, result: dict) -> None:
        with self._lock:
            self._data.setdefault(sha256, {})[service] = {**result, "ts": iso_now()}
            self._flush()

    def hashes(self) -> list[str]:
        with self._lock:
            return list(self._data)

    def _flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data, indent=1, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.path)
