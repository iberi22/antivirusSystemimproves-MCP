import types
import time
from datetime import datetime, timedelta, timezone

import pytest


def iso_now_minus(seconds: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()


@pytest.fixture()
def fake_db(monkeypatch):
    # Simple in-memory store
    store = {
        "ip": {},  # (ip) -> {verdict, last_seen}
        "ip_src": {},  # (ip, source) -> {verdict, last_seen, source}
        "domain": {},
        "domain_src": {},
        "upserts": {"ip": [], "ip_src": [], "domain": [], "domain_src": []},
    }

    from mcp_win_admin import reputation as rep

    def now_iso():
        return datetime.now(timezone.utc).isoformat()

    # IP getters
    def get_ip_reputation(ip: str, ttl_seconds=None):
        row = store["ip"].get(ip)
        if not row:
            return None
        if ttl_seconds is None or ttl_seconds < 0:
            return row
        try:
            ts = datetime.fromisoformat(row["last_seen"]).timestamp()
        except Exception:
            return None
        if ts >= (datetime.now(timezone.utc).timestamp() - int(ttl_seconds)):
            return row
        return None

    def get_ip_reputation_sources(ip: str, ttl_seconds=None):
        rows = []
        for (k_ip, src), row in store["ip_src"].items():
            if k_ip != ip:
                continue
            if ttl_seconds is None or ttl_seconds < 0:
                rows.append(row)
                continue
            try:
                ts = datetime.fromisoformat(row["last_seen"]).timestamp()
            except Exception:
                continue
            if ts >= (datetime.now(timezone.utc).timestamp() - int(ttl_seconds)):
                rows.append(row)
        return rows

    def upsert_ip_reputation(ip: str, verdict: str, source: str, metadata=None):
        store["ip"][ip] = {"ip": ip, "verdict": verdict, "last_seen": now_iso(), "source": source}
        store["upserts"]["ip"].append((ip, verdict, source))

    def upsert_ip_reputation_source(ip: str, source: str, verdict: str, metadata=None):
        store["ip_src"][(ip, source)] = {
            "ip": ip,
            "source": source,
            "verdict": verdict,
            "last_seen": now_iso(),
        }
        store["upserts"]["ip_src"].append((ip, source, verdict))

    # Domain getters
    def get_domain_reputation(domain: str, ttl_seconds=None):
        row = store["domain"].get(domain)
        if not row:
            return None
        if ttl_seconds is None or ttl_seconds < 0:
            return row
        try:
            ts = datetime.fromisoformat(row["last_seen"]).timestamp()
        except Exception:
            return None
        if ts >= (datetime.now(timezone.utc).timestamp() - int(ttl_seconds)):
            return row
        return None

    def get_domain_reputation_sources(domain: str, ttl_seconds=None):
        rows = []
        for (k_dom, src), row in store["domain_src"].items():
            if k_dom != domain:
                continue
            if ttl_seconds is None or ttl_seconds < 0:
                rows.append(row)
                continue
            try:
                ts = datetime.fromisoformat(row["last_seen"]).timestamp()
            except Exception:
                continue
            if ts >= (datetime.now(timezone.utc).timestamp() - int(ttl_seconds)):
                rows.append(row)
        return rows

    def upsert_domain_reputation(domain: str, verdict: str, source: str, metadata=None):
        store["domain"][domain] = {
            "domain": domain,
            "verdict": verdict,
            "last_seen": now_iso(),
            "source": source,
        }
        store["upserts"]["domain"].append((domain, verdict, source))

    def upsert_domain_reputation_source(domain: str, source: str, verdict: str, metadata=None):
        store["domain_src"][(domain, source)] = {
            "domain": domain,
            "source": source,
            "verdict": verdict,
            "last_seen": now_iso(),
        }
        store["upserts"]["domain_src"].append((domain, source, verdict))

    monkeypatch.setattr(rep.db, "get_ip_reputation", get_ip_reputation, raising=True)
    monkeypatch.setattr(rep.db, "get_ip_reputation_sources", get_ip_reputation_sources, raising=True)
    monkeypatch.setattr(rep.db, "upsert_ip_reputation", upsert_ip_reputation, raising=True)
    monkeypatch.setattr(rep.db, "upsert_ip_reputation_source", upsert_ip_reputation_source, raising=True)

    monkeypatch.setattr(rep.db, "get_domain_reputation", get_domain_reputation, raising=True)
    monkeypatch.setattr(rep.db, "get_domain_reputation_sources", get_domain_reputation_sources, raising=True)
    monkeypatch.setattr(rep.db, "upsert_domain_reputation", upsert_domain_reputation, raising=True)
    monkeypatch.setattr(rep.db, "upsert_domain_reputation_source", upsert_domain_reputation_source, raising=True)

    return store


@pytest.fixture(autouse=True)
def no_throttle(monkeypatch):
    # Avoid sleeping in tests; also track calls
    from mcp_win_admin import reputation as rep
    calls = []

    def fake_throttle(key: str):
        calls.append(key)

    monkeypatch.setattr(rep, "_throttle", fake_throttle, raising=True)
    monkeypatch.setattr(rep, "_MIN_INTERVAL", 0.0, raising=False)
    rep._LAST_CALL.clear()
    return calls


def test_check_ip_cache_only(fake_db):
    from mcp_win_admin import reputation as rep

    # Seed cache: overall verdict clean
    fake_db["ip"]["1.2.3.4"] = {
        "ip": "1.2.3.4",
        "verdict": "clean",
        "last_seen": iso_now_minus(10),
        "source": "seed",
    }
    # Source cache only for threatfox
    fake_db["ip_src"][("1.2.3.4", "threatfox")] = {
        "ip": "1.2.3.4",
        "source": "threatfox",
        "verdict": "unknown",
        "last_seen": iso_now_minus(10),
    }

    out = rep.check_ip("1.2.3.4", use_cloud=False, ttl_seconds=3600, sources=("threatfox", "urlhaus"))
    assert out["verdict"] == "clean"
    assert any(s["source"] == "threatfox" and s["cached"] for s in out["sources"])
    # urlhaus is not fetched because use_cloud=False
    assert not any(s["source"] == "urlhaus" and not s["cached"] for s in out["sources"])


def test_check_ip_cloud_fetch_and_cache_writes(fake_db, monkeypatch):
    from mcp_win_admin import reputation as rep

    # No overall or source cache
    
    # Mock lookups
    monkeypatch.setattr(rep, "_threatfox_lookup", lambda *a, **k: {"source": "threatfox", "verdict": "malicious"})
    monkeypatch.setattr(rep, "_urlhaus_host_lookup", lambda *a, **k: {"source": "urlhaus", "verdict": "unknown"})
    monkeypatch.setattr(rep, "_vt_ip_lookup", lambda ip, client=None: {"source": "virustotal", "verdict": "suspicious"})
    # No OTX in this test

    out = rep.check_ip("8.8.8.8", use_cloud=True, ttl_seconds=0, sources=("threatfox", "urlhaus", "virustotal"))
    # Best verdict should be malicious
    assert out["verdict"] == "malicious"
    # Ensure writes occurred per source
    assert ("8.8.8.8", "threatfox") in fake_db["ip_src"]
    assert ("8.8.8.8", "virustotal") in fake_db["ip_src"]
    assert ("8.8.8.8", "urlhaus") in fake_db["ip_src"]


def test_check_ip_ttl_by_source(fake_db):
    from mcp_win_admin import reputation as rep

    ip = "9.9.9.9"
    # Seed per-source cache: threatfox fresh, urlhaus stale
    fake_db["ip_src"][(ip, "threatfox")] = {
        "ip": ip,
        "source": "threatfox",
        "verdict": "unknown",
        "last_seen": iso_now_minus(10),
    }
    fake_db["ip_src"][(ip, "urlhaus")] = {
        "ip": ip,
        "source": "urlhaus",
        "verdict": "malicious",
        "last_seen": iso_now_minus(3600),
    }

    out = rep.check_ip(ip, use_cloud=False, sources=("threatfox", "urlhaus"), ttl_by_source={"threatfox": 3600, "urlhaus": 1})
    # Only threatfox should remain cached due to TTL filter
    assert any(s["source"] == "threatfox" and s["cached"] for s in out["sources"])
    assert not any(s["source"] == "urlhaus" and s["cached"] for s in out["sources"])


def test_check_domain_cloud_with_otx_no_key_and_vt_fallback(fake_db, monkeypatch):
    from mcp_win_admin import reputation as rep

    # Force clients
    monkeypatch.setattr(rep, "_otx_client", lambda: None)
    monkeypatch.setattr(rep, "_vt_client", lambda: object())
    # VT lookup returns None to trigger fallback dict
    monkeypatch.setattr(rep, "_vt_domain_lookup", lambda domain, client=None: None)
    monkeypatch.setattr(rep, "_otx_domain_lookup", lambda domain, client=None: {"source": "otx", "verdict": "unknown", "status": "no_api_key"})
    monkeypatch.setattr(rep, "_urlhaus_host_lookup", lambda host, client=None: {"source": "urlhaus", "verdict": "unknown"})
    monkeypatch.setattr(rep, "_threatfox_lookup", lambda qt, val, client=None: {"source": "threatfox", "verdict": "unknown"})

    out = rep.check_domain("example.com", use_cloud=True, ttl_seconds=0, sources=("threatfox", "urlhaus", "virustotal", "otx"))
    # Should include virustotal with unknown by fallback
    assert any(s["source"] == "virustotal" and s["verdict"] == "unknown" for s in out["sources"])
    # OTX without key returns unknown/no_api_key
    assert any(s["source"] == "otx" for s in out["sources"]) 
    # Upserts should exist
    assert ("example.com", "virustotal") in fake_db["domain_src"]


def test_throttle_called(no_throttle, monkeypatch):
    from mcp_win_admin import reputation as rep
    import httpx

    # Fake httpx client so helpers run without network and still call _throttle
    class FakeResp:
        def __init__(self, data):
            self._data = data
            self.status_code = 200
        def raise_for_status(self):
            return None
        def json(self):
            return self._data

    class FakeClient:
        def __init__(self, *a, **k):
            pass
        def post(self, url, json=None, data=None):
            # Return "no_result" so verdict=unknown
            if "urlhaus" in url:
                return FakeResp({"query_status": "no_result"})
            return FakeResp({})
        def get(self, url):
            return FakeResp({})
        def close(self):
            return None

    monkeypatch.setattr(httpx, "Client", FakeClient, raising=True)

    out = rep.check_domain("throttle.test", use_cloud=True, ttl_seconds=0, sources=("urlhaus",))
    assert out["domain"] == "throttle.test"
    # Our fake throttle recorded calls
    assert "urlhaus" in no_throttle
