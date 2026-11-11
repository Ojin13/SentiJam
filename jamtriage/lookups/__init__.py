"""Quota-aware lookup workers draining the persistent SQLite priority queue."""
from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Callable

from ..config import Config
from ..state import LookupCache, State, utc_day
from .services import MalwareBazaar, MetaDefender, QuotaExceeded, RateLimited, ServiceError, VirusTotal

SERVICES = ("virustotal", "malwarebazaar", "metadefender")
KEY_ENV = {"virustotal": "VT_API_KEY", "malwarebazaar": "MB_AUTH_KEY", "metadefender": "MD_API_KEY"}


def next_utc_midnight(now: float | None = None) -> float:
    dt = datetime.fromtimestamp(time.time() if now is None else now, tz=timezone.utc)
    return (dt.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)).timestamp()


# Free-tier limits. Config values above these are clamped (with a warning) unless the section says
# `premium = true`, so a typo can't burn through a key.
FREE_TIER = {
    "virustotal": {"requests_per_minute": 4, "daily_budget": 500, "monthly_budget": 15500},
}
# Defaults when a section doesn't set them. Every service always has a daily budget.
DEFAULT_DAILY = {"virustotal": 480, "malwarebazaar": 2000, "metadefender": 900}


class Limiter:
    """Per-service pacing (requests/minute) plus daily and monthly budgets, persisted in state.db.

    Every request to a service, from any command or process, goes through acquire(); the decision and
    the bookkeeping happen in one SQLite transaction (State.take_slot)."""

    def __init__(self, state: State, service: str, rpm: float, daily_budget: int | None,
                 clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep,
                 monthly_budget: int | None = None):
        self.state, self.service = state, service
        self.interval = 60.0 / max(rpm, 0.01)
        self.budget = daily_budget
        self.monthly = monthly_budget
        self.clock, self.sleep = clock, sleep
        self.last_refusal = ""

    def remaining(self) -> int | None:
        day = utc_day(self.clock())
        left = []
        if self.budget is not None:
            left.append(self.budget - self.state.quota_used(self.service, day))
        if self.monthly is not None:
            left.append(self.monthly - self.state.quota_used_month(self.service, day))
        return max(0, min(left)) if left else None

    def next_request_in(self) -> float:
        last, paused = self.state.limiter_get(self.service)
        now = self.clock()
        return max(0.0, paused - now, last + self.interval - now)

    def paused(self) -> bool:
        _, paused = self.state.limiter_get(self.service)
        return paused > self.clock()

    def acquire(self, stop: threading.Event | None = None, max_wait: float | None = None) -> bool:
        """Block until a request may be sent, and count it. False if a budget is spent, the service is
        paused for long (quota exceeded), `stop` is set, or `max_wait` seconds pass."""
        started = self.clock()
        while True:
            status, wait = self.state.take_slot(self.service, self.interval, self.clock(), self.budget, self.monthly)
            if status == "ok":
                self.last_refusal = ""
                return True
            if status in ("daily", "monthly"):
                self.last_refusal = f"{status} budget used up"
                return False
            if status == "paused" and wait > 300:
                self.last_refusal = "paused (quota exceeded)"
                return False
            if (stop is not None and stop.is_set()) or \
                    (max_wait is not None and self.clock() - started + wait > max_wait):
                self.last_refusal = "gave up waiting"
                return False
            self.sleep(min(wait, 1.0))

    def pause(self, seconds: float) -> None:
        self.state.limiter_set(self.service, paused_until=self.clock() + seconds)

    def pause_until_tomorrow(self) -> None:
        self.state.limiter_set(self.service, paused_until=next_utc_midnight(self.clock()))


class BudgetSpent(Exception):
    """A budget (daily/monthly requests or submissions) is used up, or the service is paused."""


def take(lim: Limiter, max_wait: float = 300) -> None:
    """Take one request slot or raise BudgetSpent."""
    if not lim.acquire(max_wait=max_wait):
        raise BudgetSpent(lim.last_refusal or f"no {lim.service} request slot")


# Hybrid Analysis free tier (as shown on the account page): 200 requests/min, 100 sandbox submissions/day.
HYBRID_FREE = {"requests_per_minute": 200, "daily_submissions": 100}


def hybrid_limiters(cfg: Config, state: State) -> tuple[Limiter, Limiter]:
    """(requests limiter, submissions limiter) for Hybrid Analysis, clamped to the free tier unless premium."""
    sec = cfg.section("hybridanalysis")
    rpm = float(sec.get("requests_per_minute") or 60)
    subs = int(sec.get("daily_submissions") or 95)
    if not sec.get("premium"):
        rpm = min(rpm, HYBRID_FREE["requests_per_minute"])
        subs = min(subs, HYBRID_FREE["daily_submissions"])
    requests = Limiter(state, "hybrid", rpm, int(sec.get("daily_requests") or 5000))
    submissions = Limiter(state, "hybrid-submit", float(sec.get("submissions_per_minute") or 10), subs)
    return requests, submissions


def make_client(service: str, key: str):
    return {"virustotal": VirusTotal, "malwarebazaar": MalwareBazaar, "metadefender": MetaDefender}[service](key)


def limits_for(cfg: Config, service: str) -> tuple[float, int, int | None, list[str]]:
    """(requests_per_minute, daily_budget, monthly_budget, warnings) after defaults and free-tier clamping."""
    sec = cfg.section(service)
    rpm = float(sec.get("requests_per_minute") or 4)
    daily = int(sec.get("daily_budget") or DEFAULT_DAILY.get(service, 500))
    monthly = int(sec["monthly_budget"]) if sec.get("monthly_budget") else None
    warnings = []
    ceiling = FREE_TIER.get(service)
    if ceiling and not sec.get("premium"):
        monthly = monthly or ceiling["monthly_budget"]
        for name, value in (("requests_per_minute", rpm), ("daily_budget", daily), ("monthly_budget", monthly)):
            if value > ceiling[name]:
                warnings.append(f"[{service}] {name} = {value:g} is above the free tier ({ceiling[name]}); "
                                f"using {ceiling[name]}. Set premium = true if your key really allows more.")
        rpm = min(rpm, ceiling["requests_per_minute"])
        daily = min(daily, ceiling["daily_budget"])
        monthly = min(monthly, ceiling["monthly_budget"])
    return rpm, daily, monthly, warnings


def make_limiter(cfg: Config, state: State, service: str, **kw) -> Limiter:
    rpm, daily, monthly, _ = limits_for(cfg, service)
    return Limiter(state, service, rpm, daily, monthly_budget=monthly, **kw)


def quota_warnings(cfg: Config) -> list[str]:
    return [w for s in SERVICES if cfg.section(s).get("enabled") for w in limits_for(cfg, s)[3]]


def enabled_services(cfg: Config) -> list[str]:
    out = []
    for s in SERVICES:
        if cfg.section(s).get("enabled") and cfg.key(KEY_ENV[s]):
            out.append(s)
    return out


class LookupWorker(threading.Thread):
    """Drains one service's queue in tier order. Stops cleanly at the budget; leftovers stay pending."""

    MAX_429_IN_A_ROW = 4
    MAX_ERRORS_IN_A_ROW = 5   # circuit breaker: a service that keeps failing isn't fed the rest of the budget

    def __init__(self, cfg: Config, state_path, cache: LookupCache, service: str, client=None,
                 limiter: Limiter | None = None, log: Callable[[str], None] | None = None, refresh: bool = False):
        super().__init__(daemon=True, name=f"lookup-{service}")
        self.refresh = refresh  # recheck: ignore cached answers and ask again
        self.cfg, self.cache, self.service = cfg, cache, service
        self.state = State(state_path)
        self.client = client or make_client(service, cfg.key(KEY_ENV[service]))
        self.limiter = limiter or make_limiter(cfg, self.state, service)
        self.producer_done = threading.Event()
        self.stop_event = threading.Event()
        self.log = log or (lambda m: self.state.log(m))
        self.done_count = 0
        self.stopped_reason = ""

    def run(self) -> None:
        backoff = 60.0
        in_a_row = 0
        errors_in_a_row = 0
        while not self.stop_event.is_set():
            if errors_in_a_row >= self.MAX_ERRORS_IN_A_ROW:
                self.limiter.pause(15 * 60)
                self.stopped_reason = f"{errors_in_a_row} errors in a row; paused 15 min, the rest stays pending"
                self.log(f"{self.service}: {self.stopped_reason}")
                return
            row = self.state.next_lookup(self.service)
            if row is None:
                if self.producer_done.is_set():
                    self.stopped_reason = "queue empty"
                    return
                time.sleep(0.5)
                continue
            sha = row["sha256"]
            allow = self.cfg.lookup_allowlist
            if allow is not None and sha not in allow:
                self.state.finish_lookup(self.service, sha, "skipped", "self-test: not on allowlist")
                continue
            if not self.refresh and self.cache.get(sha, self.service) is not None:
                self.state.finish_lookup(self.service, sha, "done")
                continue
            if not self.limiter.acquire(self.stop_event):
                self.stopped_reason = self.limiter.last_refusal or "paused"
                self.log(f"{self.service}: {self.stopped_reason}; remaining lookups stay pending for the next run")
                return
            try:
                result = self.client.lookup(sha)
            except RateLimited as exc:
                in_a_row += 1
                if in_a_row >= self.MAX_429_IN_A_ROW:
                    self.limiter.pause_until_tomorrow()
                    self.stopped_reason = "quota exceeded (repeated 429)"
                    self.log(f"{self.service}: repeated HTTP 429, pausing until tomorrow (UTC)")
                    return
                wait = exc.retry_after if exc.retry_after else backoff
                backoff = min(backoff * 2, 3600)
                self.log(f"{self.service}: HTTP 429, waiting {wait:.0f}s")
                self.limiter.pause(wait)
                continue
            except QuotaExceeded:
                self.limiter.pause_until_tomorrow()
                self.stopped_reason = "quota exceeded"
                return
            except ServiceError as exc:
                self.log(f"{self.service}: {exc}")
                if exc.fatal:   # e.g. a bad API key: not this file's fault, leave it pending for the next run
                    self.stopped_reason = str(exc)
                    return
                self.state.finish_lookup(self.service, sha, "error", str(exc))
                errors_in_a_row += 1
                continue
            except Exception as exc:  # noqa: BLE001  (network errors)
                self.state.finish_lookup(self.service, sha, "pending" if row["attempts"] < 3 else "error", str(exc))
                self.log(f"{self.service}: lookup error for {sha[:12]}: {exc}")
                errors_in_a_row += 1
                self.limiter.sleep(min(5 * 2 ** errors_in_a_row, 120))
                continue
            in_a_row, backoff, errors_in_a_row = 0, 60.0, 0
            self.cache.put(sha, self.service, result)
            self.state.finish_lookup(self.service, sha, "done")
            self.done_count += 1
            ents = row["entries"]
            verdict = "not found" if not result.get("found") else _short(self.service, result)
            self.log(f"{self.service}: {sha[:12]}… {verdict}  ({ents})")


def _short(service: str, r: dict) -> str:
    if service == "virustotal":
        return f"{r.get('malicious', 0)}/{r.get('total', 0)} {r.get('label', '')}".strip()
    if service == "malwarebazaar":
        return f"KNOWN MALWARE {r.get('signature', '')}".strip()
    return f"{r.get('detected', 0)}/{r.get('total', 0)}"


class LookupManager:
    def __init__(self, cfg: Config, cache: LookupCache, services: list[str] | None = None, clients: dict | None = None,
                 refresh: bool = False):
        self.cfg, self.cache, self.refresh = cfg, cache, refresh
        self.services = services if services is not None else enabled_services(cfg)
        self.workers: dict[str, LookupWorker] = {}
        self.clients = clients or {}

    def start(self) -> None:
        for s in self.services:
            w = LookupWorker(self.cfg, self.cfg.state_db, self.cache, s, client=self.clients.get(s), refresh=self.refresh)
            self.workers[s] = w
            w.start()

    def producer_finished(self) -> None:
        for w in self.workers.values():
            w.producer_done.set()

    def wait(self, timeout: float | None = None) -> None:
        deadline = None if timeout is None else time.time() + timeout
        for w in self.workers.values():
            w.join(None if deadline is None else max(0.0, deadline - time.time()))

    def stop(self) -> None:
        for w in self.workers.values():
            w.stop_event.set()
