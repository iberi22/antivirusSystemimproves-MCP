import types
from datetime import datetime, timezone

import pytest

from mcp_win_admin import reputation as rep


def test_check_ip_unknown_source_continue(monkeypatch):
    # No cache by source; unknown source should hit else: continue
    monkeypatch.setattr(rep.db, 'get_ip_reputation', lambda ip, ttl_seconds=None: None, raising=True)
    monkeypatch.setattr(rep.db, 'get_ip_reputation_sources', lambda ip, ttl_seconds=None: [], raising=True)
    out = rep.check_ip('1.2.3.4', use_cloud=True, sources=("unknownsrc",))
    assert out['verdict'] in {'unknown', 'clean', 'suspicious', 'malicious'}
    # No sources appended because it continued
    assert out['sources'] == []


def test_check_ip_upsert_exception(monkeypatch):
    # Force a cloud fetch for a known source and make DB upserts raise to hit except: pass
    monkeypatch.setattr(rep.db, 'get_ip_reputation', lambda ip, ttl_seconds=None: None, raising=True)
    monkeypatch.setattr(rep.db, 'get_ip_reputation_sources', lambda ip, ttl_seconds=None: [], raising=True)

    def fake_threatfox(qt, value, client=None):
        return {"source": "threatfox", "verdict": "unknown"}

    monkeypatch.setattr(rep, '_threatfox_lookup', fake_threatfox, raising=True)

    def boom(*a, **k):
        raise RuntimeError('db fail')

    monkeypatch.setattr(rep.db, 'upsert_ip_reputation', boom, raising=True)
    monkeypatch.setattr(rep.db, 'upsert_ip_reputation_source', boom, raising=True)

    out = rep.check_ip('5.6.7.8', use_cloud=True, sources=("threatfox",))
    assert out['sources'] and out['sources'][0]['source'] == 'threatfox'
    assert out['sources'][0]['cached'] is False


def test_check_ip_ttl_by_source_filters_and_invalid_date(monkeypatch):
    # TTL per-source filtering applied in-memory; include/exclude and malformed timestamp
    monkeypatch.setattr(rep.db, 'get_ip_reputation', lambda ip, ttl_seconds=None: None, raising=True)

    now_iso = datetime.now(timezone.utc).isoformat()
    old_iso = '1970-01-01T00:00:00+00:00'

    rows = [
        {"source": "otx", "last_seen": now_iso, "verdict": "malicious"},
        {"source": "virustotal", "last_seen": old_iso, "verdict": "unknown"},
        {"source": "abuseipdb", "last_seen": "not-a-date", "verdict": "suspicious"},
    ]
    monkeypatch.setattr(rep.db, 'get_ip_reputation_sources', lambda ip, ttl_seconds=None: rows, raising=True)

    ttl_map = {"otx": 3600, "virustotal": 0, "abuseipdb": -1}
    out = rep.check_ip('9.9.9.9', use_cloud=False, sources=("otx", "virustotal", "abuseipdb"), ttl_by_source=ttl_map)

    # otx included as cached; virustotal excluded due to old ts with ttl 0; abuseipdb included due to ttl -1
    srcs = {s['source']: s for s in out['sources']}
    assert srcs['otx']['cached'] is True and srcs['otx']['verdict'] == 'malicious'
    assert 'virustotal' not in srcs
    assert srcs['abuseipdb']['cached'] is True and srcs['abuseipdb']['verdict'] == 'suspicious'


def test_check_domain_unknown_source_continue(monkeypatch):
    monkeypatch.setattr(rep.db, 'get_domain_reputation', lambda domain, ttl_seconds=None: None, raising=True)
    monkeypatch.setattr(rep.db, 'get_domain_reputation_sources', lambda domain, ttl_seconds=None: [], raising=True)

    out = rep.check_domain('example.com', use_cloud=True, sources=("unknownsrc",))
    assert out['sources'] == [] and out['verdict'] in {'unknown', 'clean', 'suspicious', 'malicious'}


def test_check_domain_upsert_exception(monkeypatch):
    monkeypatch.setattr(rep.db, 'get_domain_reputation', lambda domain, ttl_seconds=None: None, raising=True)
    monkeypatch.setattr(rep.db, 'get_domain_reputation_sources', lambda domain, ttl_seconds=None: [], raising=True)

    def fake_tf(qt, value, client=None):
        return {"source": "threatfox", "verdict": "unknown"}

    monkeypatch.setattr(rep, '_threatfox_lookup', fake_tf, raising=True)

    def boom(*a, **k):
        raise RuntimeError('db fail')

    monkeypatch.setattr(rep.db, 'upsert_domain_reputation', boom, raising=True)
    monkeypatch.setattr(rep.db, 'upsert_domain_reputation_source', boom, raising=True)

    out = rep.check_domain('test.local', use_cloud=True, sources=("threatfox",))
    assert out['sources'] and out['sources'][0]['source'] == 'threatfox' and out['sources'][0]['cached'] is False


def test_check_domain_ttl_by_source_filters_and_invalid_date(monkeypatch):
    monkeypatch.setattr(rep.db, 'get_domain_reputation', lambda domain, ttl_seconds=None: None, raising=True)

    now_iso = datetime.now(timezone.utc).isoformat()
    old_iso = '1970-01-01T00:00:00+00:00'

    rows = [
        {"source": "otx", "last_seen": now_iso, "verdict": "malicious"},
        {"source": "virustotal", "last_seen": old_iso, "verdict": "unknown"},
        {"source": "urlhaus", "last_seen": "not-a-date", "verdict": "clean"},
    ]
    monkeypatch.setattr(rep.db, 'get_domain_reputation_sources', lambda domain, ttl_seconds=None: rows, raising=True)

    ttl_map = {"otx": 3600, "virustotal": 0, "urlhaus": -1}
    out = rep.check_domain('mal.test', use_cloud=False, sources=("otx", "virustotal", "urlhaus"), ttl_by_source=ttl_map)

    srcs = {s['source']: s for s in out['sources']}
    assert srcs['otx']['cached'] is True and srcs['otx']['verdict'] == 'malicious'
    assert 'virustotal' not in srcs
    assert srcs['urlhaus']['cached'] is True and srcs['urlhaus']['verdict'] == 'clean'


def test_otx_domain_lookup_exception(monkeypatch):
    class BadClient:
        def get(self, *a, **k):
            raise RuntimeError('boom')

    out = rep._otx_domain_lookup('example.com', client=BadClient())
    assert out['source'] == 'otx' and out['verdict'] == 'unknown' and 'error' in out


def test_check_ip_ttl_by_source_invalid_date_exclude(monkeypatch):
    # invalid last_seen with finite ttl should trigger except path and exclusion
    monkeypatch.setattr(rep.db, 'get_ip_reputation', lambda ip, ttl_seconds=None: None, raising=True)
    rows = [
        {"source": "abuseipdb", "last_seen": "not-a-date", "verdict": "suspicious"},
    ]
    monkeypatch.setattr(rep.db, 'get_ip_reputation_sources', lambda ip, ttl_seconds=None: rows, raising=True)

    ttl_map = {"abuseipdb": 3600}
    out = rep.check_ip('8.8.8.8', use_cloud=False, sources=("abuseipdb",), ttl_by_source=ttl_map)
    assert out['sources'] == []


def test_check_ip_cloud_fetch_otx_and_greynoise(monkeypatch):
    # Ensure cloud fetch branches for otx and greynoise are hit
    monkeypatch.setattr(rep.db, 'get_ip_reputation', lambda ip, ttl_seconds=None: None, raising=True)
    monkeypatch.setattr(rep.db, 'get_ip_reputation_sources', lambda ip, ttl_seconds=None: [], raising=True)

    monkeypatch.setattr(rep.db, 'upsert_ip_reputation', lambda **k: None, raising=True)
    monkeypatch.setattr(rep.db, 'upsert_ip_reputation_source', lambda **k: None, raising=True)

    monkeypatch.setattr(rep, '_otx_ip_lookup', lambda ip, client=None: {"source": "otx", "verdict": "unknown"}, raising=True)
    monkeypatch.setattr(rep, '_greynoise_ip_lookup', lambda ip, client=None: {"source": "greynoise", "verdict": "clean"}, raising=True)

    out = rep.check_ip('4.3.2.1', use_cloud=True, sources=("otx", "greynoise"))
    srcs = {s['source']: s for s in out['sources']}
    assert 'otx' in srcs and srcs['otx']['cached'] is False
    assert 'greynoise' in srcs and srcs['greynoise']['cached'] is False


def test_check_domain_ttl_by_source_invalid_date_exclude(monkeypatch):
    monkeypatch.setattr(rep.db, 'get_domain_reputation', lambda domain, ttl_seconds=None: None, raising=True)
    rows = [
        {"source": "urlhaus", "last_seen": "not-a-date", "verdict": "unknown"}
    ]
    monkeypatch.setattr(rep.db, 'get_domain_reputation_sources', lambda domain, ttl_seconds=None: rows, raising=True)

    ttl_map = {"urlhaus": 3600}
    out = rep.check_domain('bad.dom', use_cloud=False, sources=("urlhaus",), ttl_by_source=ttl_map)
    assert out['sources'] == []
