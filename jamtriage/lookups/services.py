"""Hash-only reputation lookups: VirusTotal, MalwareBazaar, MetaDefender Cloud.

Plain `requests` against the documented REST endpoints (the same ones vt-py wraps), because the rate
limiter needs the raw HTTP status and Retry-After header. Nothing here ever uploads a file.
"""
from __future__ import annotations

from datetime import datetime, timezone

import requests

USER_AGENT = "jam-triage/0.1"
TIMEOUT = 30


class RateLimited(Exception):
    def __init__(self, retry_after: float | None = None, msg: str = "rate limited"):
        super().__init__(msg)
        self.retry_after = retry_after


class QuotaExceeded(Exception):
    pass


class ServiceError(Exception):
    def __init__(self, msg: str, fatal: bool = False):
        super().__init__(msg)
        self.fatal = fatal


def _retry_after(resp: requests.Response) -> float | None:
    for h in ("Retry-After", "X-RateLimit-Reset-In"):
        v = resp.headers.get(h)
        if v:
            try:
                return float(v)
            except ValueError:
                pass
    return None


def _iso(ts) -> str:
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d")
    except (TypeError, ValueError, OSError):
        return ""


class VirusTotal:
    name = "virustotal"
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, session: requests.Session | None = None):
        self.key = api_key
        self.s = session or requests.Session()
        self.s.headers.update({"x-apikey": api_key, "User-Agent": USER_AGENT, "Accept": "application/json"})

    def lookup(self, sha256: str) -> dict:
        r = self.s.get(f"{self.BASE}/files/{sha256}", timeout=TIMEOUT)
        if r.status_code == 404:
            return {"found": False}
        if r.status_code == 429:
            raise RateLimited(_retry_after(r), "VirusTotal 429 QuotaExceededError")
        if r.status_code in (401, 403):
            raise ServiceError(f"VirusTotal {r.status_code}: check VT_API_KEY", fatal=True)
        if r.status_code != 200:
            raise ServiceError(f"VirusTotal HTTP {r.status_code}: {r.text[:200]}")
        return self.parse(r.json())

    @staticmethod
    def parse(doc: dict) -> dict:
        a = (doc.get("data") or {}).get("attributes") or {}
        stats = a.get("last_analysis_stats") or {}
        results = a.get("last_analysis_results") or {}
        dets = sorted([eng, (res or {}).get("result") or ""] for eng, res in results.items()
                      if (res or {}).get("category") == "malicious")
        total = sum(int(stats.get(k, 0)) for k in ("malicious", "suspicious", "undetected", "harmless"))
        ptc = a.get("popular_threat_classification") or {}
        return {
            "found": True,
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "total": total,
            "label": ptc.get("suggested_threat_label", ""),
            "families": [x.get("value", "") for x in ptc.get("popular_threat_name", []) or []][:5],
            "detections": dets[:40],
            "first_seen": _iso(a.get("first_submission_date")),
            "type": a.get("type_description", ""),
            "names": (a.get("names") or [])[:5],
            "sandbox_verdicts": [
                {"sandbox": name, "category": (v or {}).get("category", ""),
                 "names": list((v or {}).get("malware_names") or [])[:5]}
                for name, v in (a.get("sandbox_verdicts") or {}).items()][:10],
        }

    def behaviour_summary(self, sha256: str) -> dict | None:
        r = self.s.get(f"{self.BASE}/files/{sha256}/behaviour_summary", timeout=TIMEOUT)
        if r.status_code == 404:
            return None
        if r.status_code == 429:
            raise RateLimited(_retry_after(r))
        if r.status_code != 200:
            raise ServiceError(f"VirusTotal behaviour HTTP {r.status_code}")
        return r.json().get("data") or {}

    def upload(self, path, size: int) -> str:
        """Upload one file (opt-in only, via `triage upload`). Returns the analysis id."""
        url = f"{self.BASE}/files"
        if size > 32 * 1024 * 1024:
            r = self.s.get(f"{self.BASE}/files/upload_url", timeout=TIMEOUT)
            if r.status_code != 200:
                raise ServiceError(f"upload_url HTTP {r.status_code}: {r.text[:200]}")
            url = r.json()["data"]
        with open(path, "rb") as fh:
            r = self.s.post(url, files={"file": (path.name, fh)}, timeout=600)
        if r.status_code == 429:
            raise RateLimited(_retry_after(r))
        if r.status_code not in (200, 201):
            raise ServiceError(f"VirusTotal upload HTTP {r.status_code}: {r.text[:200]}")
        return r.json()["data"]["id"]


class MalwareBazaar:
    name = "malwarebazaar"
    URL = "https://mb-api.abuse.ch/api/v1/"

    def __init__(self, auth_key: str, session: requests.Session | None = None):
        self.s = session or requests.Session()
        self.s.headers.update({"Auth-Key": auth_key, "User-Agent": USER_AGENT})

    def lookup(self, sha256: str) -> dict:
        r = self.s.post(self.URL, data={"query": "get_info", "hash": sha256}, timeout=TIMEOUT)
        if r.status_code == 429:
            raise RateLimited(_retry_after(r))
        if r.status_code in (401, 403):
            raise ServiceError(f"MalwareBazaar {r.status_code}: check MB_AUTH_KEY", fatal=True)
        if r.status_code != 200:
            raise ServiceError(f"MalwareBazaar HTTP {r.status_code}")
        return self.parse(r.json())

    @staticmethod
    def parse(doc: dict) -> dict:
        status = doc.get("query_status")
        if status in ("hash_not_found", "no_results"):
            return {"found": False}
        if status != "ok":
            if status in ("unknown_auth_key", "user_blacklisted"):
                raise ServiceError(f"MalwareBazaar: {status}", fatal=True)
            raise ServiceError(f"MalwareBazaar: {status}")
        item = (doc.get("data") or [{}])[0]
        return {"found": True, "signature": item.get("signature") or "", "tags": item.get("tags") or [],
                "first_seen": item.get("first_seen") or "", "file_type": item.get("file_type") or ""}


class MetaDefender:
    name = "metadefender"
    BASE = "https://api.metadefender.com/v4"

    def __init__(self, api_key: str, session: requests.Session | None = None):
        self.s = session or requests.Session()
        self.s.headers.update({"apikey": api_key, "User-Agent": USER_AGENT})

    def lookup(self, sha256: str) -> dict:
        r = self.s.get(f"{self.BASE}/hash/{sha256}", timeout=TIMEOUT)
        if r.status_code == 404:
            return {"found": False}
        if r.status_code == 429:
            raise RateLimited(_retry_after(r))
        if r.status_code in (401, 403):
            raise ServiceError(f"MetaDefender {r.status_code}: check MD_API_KEY", fatal=True)
        if r.status_code != 200:
            raise ServiceError(f"MetaDefender HTTP {r.status_code}")
        return self.parse(r.json())

    @staticmethod
    def parse(doc: dict) -> dict:
        sr = doc.get("scan_results") or {}
        details = sr.get("scan_details") or {}
        threats = sorted({(v or {}).get("threat_found") for v in details.values() if (v or {}).get("threat_found")})
        total = int(sr.get("total_avs") or 0)
        return {"found": True, "detected": int(sr.get("total_detected_avs") or 0),
                "total": total, "result": sr.get("scan_all_result_a", ""),
                "threats": threats[:10],
                # never uploaded to MetaDefender: the answer is a single engine's hash reputation, not a scan
                "reputation_only": total <= 1 and not doc.get("data_id")}
