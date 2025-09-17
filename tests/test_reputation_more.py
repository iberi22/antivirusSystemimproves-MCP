import os
from datetime import datetime, timezone, timedelta
import types
import pytest

from mcp_win_admin import reputation as rep


def test_clients_env_none_and_present(monkeypatch):
    import httpx
    # Ensure missing env -> None
    monkeypatch.delenv('VT_API_KEY', raising=False)
    monkeypatch.delenv('OTX_API_KEY', raising=False)
    monkeypatch.delenv('GREYNOISE_API_KEY', raising=False)
    monkeypatch.delenv('ABUSEIPDB_API_KEY', raising=False)
    assert rep._vt_client() is None
    assert rep._otx_client() is None
    assert rep._greynoise_client() is None
    assert rep._abuseipdb_client() is None

    # With env -> returns a client; stub httpx.Client
    class DummyClient:
        def __init__(self, *a, **k):
            self.kw = k
    monkeypatch.setattr(httpx, 'Client', DummyClient, raising=True)
    monkeypatch.setenv('VT_API_KEY', 'k')
    monkeypatch.setenv('OTX_API_KEY', 'k')
    monkeypatch.setenv('GREYNOISE_API_KEY', 'k')
    monkeypatch.setenv('ABUSEIPDB_API_KEY', 'k')
    assert isinstance(rep._vt_client(), DummyClient)
    assert isinstance(rep._otx_client(), DummyClient)
    assert isinstance(rep._greynoise_client(), DummyClient)
    assert isinstance(rep._abuseipdb_client(), DummyClient)


def test_threatfox_lookup_ok_unknown_and_error(monkeypatch):
    import httpx
    events = {'closed': False}

    class Resp:
        def __init__(self, data, status_code=200):
            self._data = data
            self.status_code = status_code
        def raise_for_status(self):
            if self.status_code >= 400:
                raise httpx.HTTPError('bad')
        def json(self):
            return self._data

    class Client:
        def __init__(self, *a, **k):
            pass
        def post(self, url, json=None):
            # first call ok with data, second call ok without data
            if json and json.get('search_term') == 'ioc-ok':
                return Resp({'query_status': 'ok', 'data': [1, 2]})
            elif json and json.get('search_term') == 'ioc-empty':
                return Resp({'query_status': 'ok', 'data': []})
            return Resp({}, status_code=500)
        def close(self):
            events['closed'] = True

    monkeypatch.setattr(httpx, 'Client', Client, raising=True)

    r1 = rep._threatfox_lookup('ip', 'ioc-ok', client=None)
    assert r1['verdict'] == 'malicious' and r1['source'] == 'threatfox'
    r2 = rep._threatfox_lookup('ip', 'ioc-empty', client=None)
    assert r2['verdict'] == 'unknown' and 'status' in r2
    r3 = rep._threatfox_lookup('ip', 'ioc-err', client=None)
    assert r3['verdict'] == 'unknown' and 'error' in r3
    assert events['closed'] is True


def test_urlhaus_lookup_ok_unknown_and_error(monkeypatch):
    import httpx
    events = {'closed': False}

    class Resp:
        def __init__(self, data, status_code=200):
            self._data = data
            self.status_code = status_code
        def raise_for_status(self):
            if self.status_code >= 400:
                raise httpx.HTTPError('bad')
        def json(self):
            return self._data

    class Client:
        def __init__(self, *a, **k):
            pass
        def post(self, url, data=None):
            if data and data.get('host') == 'ok.example':
                return Resp({'query_status': 'ok', 'urls': [1]})
            elif data and data.get('host') == 'none.example':
                return Resp({'query_status': 'no_result'})
            return Resp({}, status_code=500)
        def close(self):
            events['closed'] = True

    monkeypatch.setattr(httpx, 'Client', Client, raising=True)
    r1 = rep._urlhaus_host_lookup('ok.example', client=None)
    assert r1['verdict'] == 'malicious'
    r2 = rep._urlhaus_host_lookup('none.example', client=None)
    assert r2['verdict'] == 'unknown'
    r3 = rep._urlhaus_host_lookup('err.example', client=None)
    assert r3['verdict'] == 'unknown' and 'error' in r3
    assert events['closed'] is True


def test_otx_ip_domain_variants(monkeypatch):
    import httpx

    class Resp:
        def __init__(self, code=200, data=None):
            self.status_code = code
            self._data = data or {}
        def raise_for_status(self):
            if self.status_code >= 400:
                raise httpx.HTTPError('bad')
        def json(self):
            return self._data

    class Client:
        def get(self, url):
            if 'IPv4' in url:
                if 'notfound' in url:
                    return Resp(404)
                if 'pulses1' in url:
                    return Resp(200, {'pulse_info': {'count': 1}})
                return Resp(200, {'pulse_info': {'count': 0}})
            else:
                if 'notfound' in url:
                    return Resp(404)
                if 'pulses2' in url:
                    return Resp(200, {'pulse_info': {'count': 2}})
                return Resp(200, {'pulse_info': {'count': 0}})

    # No key
    monkeypatch.setenv('OTX_API_KEY', '', prepend=False)
    assert rep._otx_ip_lookup('1.1.1.1', client=None)['status'] == 'no_api_key'
    assert rep._otx_domain_lookup('example.com', client=None)['status'] == 'no_api_key'

    # With client
    c = Client()
    assert rep._otx_ip_lookup('notfound', client=c)['status'] == 404
    assert rep._otx_ip_lookup('pulses1', client=c)['verdict'] == 'malicious'
    assert rep._otx_ip_lookup('none', client=c)['verdict'] == 'unknown'

    assert rep._otx_domain_lookup('notfound', client=c)['status'] == 404
    assert rep._otx_domain_lookup('pulses2', client=c)['verdict'] == 'malicious'
    assert rep._otx_domain_lookup('none', client=c)['verdict'] == 'unknown'

    # Exception path
    class BadClient:
        def get(self, url):
            raise httpx.HTTPError('boom')
    out = rep._otx_ip_lookup('x', client=BadClient())
    assert out['verdict'] == 'unknown' and 'error' in out


def test_greynoise_variants(monkeypatch):
    import httpx

    class Resp:
        def __init__(self, code=200, data=None):
            self.status_code = code
            self._data = data or {}
        def raise_for_status(self):
            if self.status_code >= 400:
                raise httpx.HTTPError('bad')
        def json(self):
            return self._data

    class Client:
        def get(self, url):
            if '404' in url:
                return Resp(404)
            if 'riot' in url:
                return Resp(200, {'riot': True, 'noise': False})
            if 'noise' in url:
                return Resp(200, {'riot': False, 'noise': True})
            return Resp(200, {'riot': False, 'noise': False})

    # No key
    monkeypatch.setenv('GREYNOISE_API_KEY', '', prepend=False)
    assert rep._greynoise_ip_lookup('1.2.3.4', client=None)['status'] == 'no_api_key'

    c = Client()
    assert rep._greynoise_ip_lookup('riot', client=c)['verdict'] == 'clean'
    assert rep._greynoise_ip_lookup('noise', client=c)['verdict'] == 'suspicious'
    assert rep._greynoise_ip_lookup('x404', client=c)['status'] == 404

    class Bad:
        def get(self, url):
            raise httpx.HTTPError('bad')
    out = rep._greynoise_ip_lookup('x', client=Bad())
    assert out['verdict'] == 'unknown' and 'error' in out


def test_abuseipdb_variants(monkeypatch):
    import httpx

    class Resp:
        def __init__(self, code=200, data=None):
            self.status_code = code
            self._data = data or {}
        def raise_for_status(self):
            if self.status_code >= 400:
                raise httpx.HTTPError('bad')
        def json(self):
            return self._data

    class Client:
        def get(self, url):
            if '404' in url:
                return Resp(404)
            if 'score80' in url:
                return Resp(200, {'data': {'abuseConfidenceScore': 80}})
            if 'score10' in url:
                return Resp(200, {'data': {'abuseConfidenceScore': 10}})
            return Resp(200, {'data': {'abuseConfidenceScore': 0}})

    # No key
    monkeypatch.setenv('ABUSEIPDB_API_KEY', '', prepend=False)
    assert rep._abuseipdb_ip_lookup('a', client=None)['status'] == 'no_api_key'

    c = Client()
    assert rep._abuseipdb_ip_lookup('score80', client=c)['verdict'] == 'malicious'
    assert rep._abuseipdb_ip_lookup('score10', client=c)['verdict'] == 'suspicious'
    assert rep._abuseipdb_ip_lookup('404', client=c)['status'] == 404

    class Bad:
        def get(self, url):
            raise httpx.HTTPError('bad')
    out = rep._abuseipdb_ip_lookup('x', client=Bad())
    assert out['verdict'] == 'unknown' and 'error' in out


def test_vt_ip_domain_variants(monkeypatch):
    import httpx

    class Resp:
        def __init__(self, code=200, data=None):
            self.status_code = code
            self._data = data or {}
        def raise_for_status(self):
            if self.status_code >= 400:
                raise httpx.HTTPError('bad')
        def json(self):
            return self._data

    class Client:
        def get(self, url):
            if '404' in url:
                return Resp(404)
            if 'mal' in url:
                return Resp(200, {'data': {'attributes': {'last_analysis_stats': {'malicious': 2}, 'reputation': 1}}})
            if 'susp' in url:
                return Resp(200, {'data': {'attributes': {'last_analysis_stats': {'malicious': 0}, 'reputation': 5}}})
            return Resp(200, {'data': {'attributes': {'last_analysis_stats': {'malicious': 0}, 'reputation': 0}}})

    c = Client()
    assert rep._vt_ip_lookup('404', client=c)['status'] == 404
    assert rep._vt_ip_lookup('mal', client=c)['verdict'] == 'malicious'
    assert rep._vt_ip_lookup('susp', client=c)['verdict'] == 'suspicious'
    assert rep._vt_ip_lookup('none', client=c)['verdict'] == 'unknown'

    assert rep._vt_domain_lookup('404', client=c)['status'] == 404
    assert rep._vt_domain_lookup('mal', client=c)['verdict'] == 'malicious'
    assert rep._vt_domain_lookup('susp', client=c)['verdict'] == 'suspicious'

    class Bad:
        def get(self, url):
            raise httpx.HTTPError('bad')
    assert rep._vt_ip_lookup('x', client=Bad())['verdict'] == 'unknown'
    assert rep._vt_domain_lookup('x', client=Bad())['verdict'] == 'unknown'

    # None client returns None
    assert rep._vt_ip_lookup('x', client=None) is None
    assert rep._vt_domain_lookup('x', client=None) is None


def test_check_ip_cache_ttl_by_source_and_cloud_fetch(monkeypatch):
    # Prepare cache with one fresh (threatfox) and one stale (urlhaus)
    now = datetime.now(timezone.utc)
    fresh = now.isoformat()
    stale = (now - timedelta(days=10)).isoformat()

    def get_ip_reputation(ip, ttl_seconds=None):
        return None

    def get_ip_reputation_sources(ip, ttl_seconds=None):
        return [
            {'source': 'threatfox', 'verdict': 'malicious', 'last_seen': fresh},
            {'source': 'urlhaus', 'verdict': 'unknown', 'last_seen': stale},
        ]

    calls = []
    def upsert_ip_reputation(**kw):
        calls.append(('agg', kw))
    def upsert_ip_reputation_source(**kw):
        calls.append(('src', kw))

    monkeypatch.setattr(rep.db, 'get_ip_reputation', get_ip_reputation, raising=True)
    monkeypatch.setattr(rep.db, 'get_ip_reputation_sources', get_ip_reputation_sources, raising=True)
    monkeypatch.setattr(rep.db, 'upsert_ip_reputation', upsert_ip_reputation, raising=True)
    monkeypatch.setattr(rep.db, 'upsert_ip_reputation_source', upsert_ip_reputation_source, raising=True)

    # Cloud helpers
    monkeypatch.setattr(rep, '_threatfox_lookup', lambda *a, **k: {'source': 'threatfox', 'verdict': 'malicious'}, raising=True)
    monkeypatch.setattr(rep, '_urlhaus_host_lookup', lambda *a, **k: {'source': 'urlhaus', 'verdict': 'malicious'}, raising=True)
    monkeypatch.setattr(rep, '_vt_ip_lookup', lambda *a, **k: {'source': 'virustotal', 'verdict': 'unknown'}, raising=True)

    out = rep.check_ip('8.8.8.8', use_cloud=True, ttl_seconds=None, ttl_by_source={'threatfox': 3600, 'urlhaus': 1}, sources=('threatfox', 'urlhaus', 'virustotal'))
    # threatfox came from cache, urlhaus fetched, virustotal fetched
    cached = [s for s in out['sources'] if s.get('cached')]
    fetched = [s for s in out['sources'] if not s.get('cached')]
    assert any(s['source']=='threatfox' and s['cached'] for s in cached)
    assert any(s['source']=='urlhaus' and not s['cached'] for s in fetched)
    assert any(s['source']=='virustotal' for s in fetched)
    # upserts called for fetched only
    assert any(t=='agg' for t, _ in calls) and any(t=='src' for t, _ in calls)


def test_check_ip_no_cloud_only_cache(monkeypatch):
    # Only cached entries should appear when use_cloud=False
    def get_ip_reputation(ip, ttl_seconds=None):
        return {'verdict': 'unknown'}
    def get_ip_reputation_sources(ip, ttl_seconds=None):
        return [{'source': 'urlhaus', 'verdict': 'unknown', 'last_seen': datetime.now(timezone.utc).isoformat()}]
    monkeypatch.setattr(rep.db, 'get_ip_reputation', get_ip_reputation, raising=True)
    monkeypatch.setattr(rep.db, 'get_ip_reputation_sources', get_ip_reputation_sources, raising=True)
    out = rep.check_ip('1.1.1.1', use_cloud=False, sources=('urlhaus',))
    assert len(out['sources']) == 1 and out['sources'][0]['cached'] is True


def test_check_domain_cloud_and_upserts(monkeypatch):
    # No cache, all fetched, verify upserts
    def get_domain_reputation(domain, ttl_seconds=None):
        return None
    def get_domain_reputation_sources(domain, ttl_seconds=None):
        return []

    calls = []
    def upsert_domain_reputation(**kw):
        calls.append(('agg', kw))
    def upsert_domain_reputation_source(**kw):
        calls.append(('src', kw))

    monkeypatch.setattr(rep.db, 'get_domain_reputation', get_domain_reputation, raising=True)
    monkeypatch.setattr(rep.db, 'get_domain_reputation_sources', get_domain_reputation_sources, raising=True)
    monkeypatch.setattr(rep.db, 'upsert_domain_reputation', upsert_domain_reputation, raising=True)
    monkeypatch.setattr(rep.db, 'upsert_domain_reputation_source', upsert_domain_reputation_source, raising=True)

    monkeypatch.setattr(rep, '_threatfox_lookup', lambda *a, **k: {'source': 'threatfox', 'verdict': 'unknown'}, raising=True)
    monkeypatch.setattr(rep, '_urlhaus_host_lookup', lambda *a, **k: {'source': 'urlhaus', 'verdict': 'malicious'}, raising=True)
    monkeypatch.setattr(rep, '_vt_domain_lookup', lambda *a, **k: {'source': 'virustotal', 'verdict': 'suspicious'}, raising=True)

    out = rep.check_domain('example.com', use_cloud=True, sources=('threatfox','urlhaus','virustotal'))
    assert {s['source'] for s in out['sources']} == {'threatfox','urlhaus','virustotal'}
    assert any(t=='agg' for t, _ in calls) and any(t=='src' for t, _ in calls)


def test_reputation_throttle_sleep(monkeypatch):
    # Force _MIN_INTERVAL and check sleep called
    t = {'now': 0.0}
    def mono():
        return t['now']
    slept = {'s': 0.0}
    def sleep(d):
        slept['s'] += d
    monkeypatch.setattr(rep, '_MIN_INTERVAL', 1.0, raising=False)
    monkeypatch.setattr(rep, 'time', types.SimpleNamespace(monotonic=mono, sleep=sleep))
    # Priming: set last call in the past by >= interval to avoid initial sleep
    rep._LAST_CALL['k'] = -1.0
    rep._throttle('k')
    t['now'] = 0.1
    rep._throttle('k')
    assert slept['s'] == pytest.approx(0.9, rel=1e-3)
