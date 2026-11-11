import pytest

from jamtriage.lookups import Limiter, LookupWorker, next_utc_midnight
from jamtriage.lookups.services import MalwareBazaar, MetaDefender, RateLimited, ServiceError, VirusTotal
from jamtriage.state import LookupCache, State


class FakeClock:
    def __init__(self, t=1_700_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


def test_limiter_paces_and_stops_at_budget(tmp_path):
    st = State(tmp_path / "s.db")
    clock = FakeClock()
    lim = Limiter(st, "virustotal", rpm=4, daily_budget=3, clock=clock, sleep=clock.sleep)
    times = []
    for _ in range(3):
        assert lim.acquire()
        times.append(clock.t)
    assert times[1] - times[0] >= 15 and times[2] - times[1] >= 15
    assert lim.remaining() == 0
    assert not lim.acquire()          # budget spent: caller leaves the rest pending


def test_limiter_state_survives_restart(tmp_path):
    st = State(tmp_path / "s.db")
    clock = FakeClock()
    Limiter(st, "vt", rpm=4, daily_budget=10, clock=clock, sleep=clock.sleep).acquire()
    lim2 = Limiter(State(tmp_path / "s.db"), "vt", rpm=4, daily_budget=10, clock=clock, sleep=clock.sleep)
    assert lim2.next_request_in() == pytest.approx(15, abs=0.01)
    assert lim2.remaining() == 9


def test_next_utc_midnight():
    assert next_utc_midnight(0) == 86400


class FakeClient:
    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def lookup(self, sha):
        self.calls.append(sha)
        a = self.answers.get(sha, {"found": False})
        if isinstance(a, Exception):
            self.answers[sha] = {"found": False}   # succeed on retry
            raise a
        return a


def _worker(cfg, client, budget=100, rpm=6000):
    st = State(cfg.state_db)
    cache = LookupCache(cfg.cache_file)
    lim = Limiter(st, "virustotal", rpm=rpm, daily_budget=budget)
    w = LookupWorker(cfg, cfg.state_db, cache, "virustotal", client=client, limiter=lim, log=lambda m: None)
    return w, st, cache


def test_worker_tier_order_cache_and_budget(cfg):
    client = FakeClient({"h1": {"found": True, "malicious": 0, "total": 70}})
    w, st, cache = _worker(cfg, client, budget=2)
    cache.put("cached", "virustotal", {"found": False})
    st.enqueue_lookup("virustotal", "h3", 3, "e1")
    st.enqueue_lookup("virustotal", "h2", 2, "e1")
    st.enqueue_lookup("virustotal", "h1", 1, "e1")
    st.enqueue_lookup("virustotal", "cached", 1, "e2")
    st.enqueue_lookup("virustotal", "h4", 1, "e3")
    w.producer_done.set()
    w.run()
    # tier 1 first (cached answer reused for free), budget of 2 stops before tier 3
    assert client.calls == ["h1", "h4"]
    assert st.lookup_status("virustotal", "cached") == "done"
    assert st.lookup_status("virustotal", "h2") == "pending" and st.lookup_status("virustotal", "h3") == "pending"
    assert w.stopped_reason == "daily budget used up"
    assert cache.get("h1", "virustotal")["total"] == 70


def test_worker_retries_after_429(cfg):
    client = FakeClient({"h1": RateLimited(retry_after=0.01)})
    w, st, cache = _worker(cfg, client)
    st.enqueue_lookup("virustotal", "h1", 1, "e1")
    w.producer_done.set()
    w.run()
    assert client.calls == ["h1", "h1"]
    assert st.lookup_status("virustotal", "h1") == "done"


def test_worker_allowlist(cfg):
    cfg.lookup_allowlist = {"ok"}
    client = FakeClient({})
    w, st, _ = _worker(cfg, client)
    st.enqueue_lookup("virustotal", "nope", 1, "e")
    st.enqueue_lookup("virustotal", "ok", 1, "e")
    w.producer_done.set()
    w.run()
    assert client.calls == ["ok"]
    assert st.lookup_status("virustotal", "nope") == "skipped"


def test_enqueue_dedupes_across_entries(tmp_path):
    st = State(tmp_path / "s.db")
    st.enqueue_lookup("virustotal", "h", 3, "a")
    st.enqueue_lookup("virustotal", "h", 1, "b")
    row = st.next_lookup("virustotal")
    assert row["tier"] == 1 and "a" in row["entries"] and "b" in row["entries"]
    assert st.pending_count("virustotal") == 1


def test_service_parsers():
    vt = VirusTotal.parse({"data": {"attributes": {
        "last_analysis_stats": {"malicious": 60, "suspicious": 1, "undetected": 9, "harmless": 0},
        "last_analysis_results": {"A": {"category": "malicious", "result": "EICAR-Test-File"},
                                  "B": {"category": "undetected", "result": None}},
        "popular_threat_classification": {"suggested_threat_label": "virus.eicar/test"},
        "first_submission_date": 1148301722}}})
    assert vt["malicious"] == 60 and vt["total"] == 70 and vt["detections"] == [["A", "EICAR-Test-File"]]
    assert vt["first_seen"] == "2006-05-22"
    assert MalwareBazaar.parse({"query_status": "hash_not_found"}) == {"found": False}
    mb = MalwareBazaar.parse({"query_status": "ok", "data": [{"signature": "LummaStealer", "tags": ["exe"]}]})
    assert mb["signature"] == "LummaStealer"
    with pytest.raises(ServiceError):
        MalwareBazaar.parse({"query_status": "unknown_auth_key"})
    md = MetaDefender.parse({"scan_results": {"total_detected_avs": 3, "total_avs": 20,
                                              "scan_details": {"X": {"threat_found": "EICAR"}}}})
    assert md["detected"] == 3 and md["threats"] == ["EICAR"]
