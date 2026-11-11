"""Request throttling: nothing may send more requests than the configured (and free-tier) limits allow."""
from __future__ import annotations

import copy
import threading

import pytest

from jamtriage.config import DEFAULTS, Config
from jamtriage.lookups import Limiter, LookupWorker, limits_for, make_limiter
from jamtriage.lookups.services import ServiceError
from jamtriage.state import LookupCache, State

from .test_lookups import FakeClock


def _cfg(tmp_path, **sections):
    raw = copy.deepcopy(DEFAULTS)
    raw["paths"] = {"data": str(tmp_path / "data"), "out": str(tmp_path / "out"), "rules": "rules"}
    for name, values in sections.items():
        raw[name].update(values)
    c = Config(root=tmp_path, raw=raw, platform="macos")
    c.ensure_dirs()
    return c


def test_budget_holds_across_threads_and_processes(tmp_path):
    """8 threads over 2 separate connections (as two processes would have) race for a budget of 7."""
    db = tmp_path / "s.db"
    states = [State(db), State(db)]
    granted = []
    lock = threading.Lock()

    def worker(i):
        lim = Limiter(states[i % 2], "virustotal", rpm=6_000_000, daily_budget=7)
        while lim.acquire(max_wait=2):
            with lock:
                granted.append(i)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert len(granted) == 7
    assert State(db).quota_used("virustotal") == 7


def test_pacing_holds_across_two_limiters(tmp_path):
    """Two commands running at once share one pace: 4/min means 15 s apart, whoever asks."""
    clock = FakeClock()
    db = tmp_path / "s.db"
    a = Limiter(State(db), "virustotal", rpm=4, daily_budget=100, clock=clock, sleep=clock.sleep)
    b = Limiter(State(db), "virustotal", rpm=4, daily_budget=100, clock=clock, sleep=clock.sleep)
    times = []
    for lim in (a, b, a, b):
        assert lim.acquire()
        times.append(clock.t)
    assert all(t2 - t1 >= 15 for t1, t2 in zip(times, times[1:], strict=False))


def test_monthly_budget_spans_days(tmp_path):
    clock = FakeClock(1_700_000_000.0)   # 2023-11-14
    lim = Limiter(State(tmp_path / "s.db"), "virustotal", rpm=6000, daily_budget=3, monthly_budget=5,
                  clock=clock, sleep=clock.sleep)
    n = 0
    for _day in range(4):
        while lim.acquire():
            n += 1
        assert lim.last_refusal.startswith(("daily", "monthly"))
        clock.t += 86400
    assert n == 5 and lim.last_refusal.startswith("monthly")


def test_free_tier_ceiling_clamps_typos(tmp_path):
    cfg = _cfg(tmp_path, virustotal={"requests_per_minute": 40, "daily_budget": 5000, "monthly_budget": 99999})
    rpm, daily, monthly, warnings = limits_for(cfg, "virustotal")
    assert (rpm, daily, monthly) == (4, 500, 15500) and len(warnings) == 3
    cfg2 = _cfg(tmp_path / "p", virustotal={"requests_per_minute": 40, "daily_budget": 5000, "premium": True})
    assert limits_for(cfg2, "virustotal")[:2] == (40, 5000)


def test_every_service_has_a_daily_budget(tmp_path):
    cfg = _cfg(tmp_path)
    for svc in ("virustotal", "malwarebazaar", "metadefender"):
        cfg.raw[svc].pop("daily_budget", None)
        lim = make_limiter(cfg, State(cfg.state_db), svc)
        assert lim.budget and lim.budget <= 2000, svc


class _Failing:
    def __init__(self, exc):
        self.exc, self.calls = exc, 0

    def lookup(self, sha):
        self.calls += 1
        raise self.exc


@pytest.mark.parametrize("exc", [ServiceError("HTTP 503"), ConnectionError("network down")])
def test_circuit_breaker_stops_a_failing_service(tmp_path, exc):
    cfg = _cfg(tmp_path)
    st = State(cfg.state_db)
    for i in range(40):
        st.enqueue_lookup("virustotal", f"h{i:02d}", 1, "e")
    clock = FakeClock()
    client = _Failing(exc)
    lim = Limiter(st, "virustotal", rpm=6000, daily_budget=480, clock=clock, sleep=clock.sleep)
    w = LookupWorker(cfg, cfg.state_db, LookupCache(cfg.cache_file), "virustotal", client=client, limiter=lim,
                     log=lambda m: None)
    w.producer_done.set()
    w.run()
    assert client.calls == LookupWorker.MAX_ERRORS_IN_A_ROW
    assert st.quota_used("virustotal", "2023-11-14") == LookupWorker.MAX_ERRORS_IN_A_ROW
    assert st.pending_count("virustotal") >= 40 - LookupWorker.MAX_ERRORS_IN_A_ROW
    assert lim.paused()


def test_per_entry_cap_applies_to_every_service(tmp_path):
    from jamtriage.checks import EntryContext
    from jamtriage.models import FileRecord
    from jamtriage.pipeline import Pipeline

    cfg = _cfg(tmp_path)
    pipe = Pipeline(cfg)
    pipe.services = ["virustotal", "malwarebazaar", "metadefender"]
    files = [FileRecord(path=f"unwrapped/pyinstaller/01/lib{i}.pyd", size=1000 + i, kind="pe",
                        origin="unwrapped", sha256=f"{i:064x}") for i in range(300)]
    ctx = EntryContext(cfg=cfg, slug="big", builds_root=tmp_path, tools={}, files=files)
    plan = pipe.lookup_plan(ctx)
    for svc, items in plan.items():
        cap = cfg.section(svc)["max_lookups_per_entry"]
        assert len(items) <= cap + 10, (svc, len(items))


def test_vt_upload_and_behaviour_share_the_lookup_budget(tmp_path):
    from jamtriage.sandbox.detonate import Refused, _vt_slot

    cfg = _cfg(tmp_path, virustotal={"daily_budget": 2})
    st = State(cfg.state_db)
    _vt_slot(cfg)
    assert st.quota_used("virustotal") == 1
    st.limiter_set("virustotal", last_request=0)     # skip the 15 s pacing for the test
    _vt_slot(cfg)
    with pytest.raises(Refused):
        _vt_slot(cfg)                                # budget spent: no request is sent
    assert st.quota_used("virustotal") == 2


def test_sandbox_polling_is_capped(monkeypatch):
    from jamtriage.sandbox import detonate

    slept = []
    monkeypatch.setattr(detonate.time, "sleep", lambda s: slept.append(s))
    p = detonate._Poller(20, longest=120, max_polls=5)
    assert [p.wait() for _ in range(7)] == [True] * 5 + [False] * 2
    assert slept[0] == 20 and slept[-1] <= 120 and slept == sorted(slept)
