import os
import sys
import types
from pathlib import Path

import pytest

from mcp_win_admin import av


def test_vt_lookup_no_key_returns_none(monkeypatch):
    monkeypatch.delenv('VT_API_KEY', raising=False)
    out = av.vt_lookup_hash('a'*64)
    assert out is None


def test_vt_lookup_parses_stats_and_404_and_exception(monkeypatch):
    import httpx

    monkeypatch.setenv('VT_API_KEY', 'dummy')

    class Resp:
        def __init__(self, code=200, data=None):
            self.status_code = code
            self._data = data or {}
        def raise_for_status(self):
            if self.status_code >= 400 and self.status_code != 404:
                raise httpx.HTTPError('boom')
        def json(self):
            return self._data

    class Client:
        def __init__(self, *a, **k):
            self._mode = 'ok'
        def get(self, url, headers=None):
            if self._mode == 'ok-mal':
                return Resp(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "suspicious": 0, "harmless": 0, "undetected": 0}}}})
            if self._mode == 'ok-susp':
                return Resp(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 1, "harmless": 0, "undetected": 0}}}})
            if self._mode == 'ok-clean':
                return Resp(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 2, "undetected": 5}}}})
            if self._mode == '404':
                return Resp(404, {})
            if self._mode == 'error':
                return Resp(500, {})
            return Resp(200, {})
        def close(self):
            return None

    client = Client()
    # malicious
    client._mode = 'ok-mal'
    out = av.vt_lookup_hash('b'*64, client=client)
    assert out['verdict'] == 'malicious'
    # suspicious
    client._mode = 'ok-susp'
    out = av.vt_lookup_hash('b'*64, client=client)
    assert out['verdict'] == 'suspicious'
    # clean
    client._mode = 'ok-clean'
    out = av.vt_lookup_hash('b'*64, client=client)
    assert out['verdict'] == 'clean'
    # 404
    client._mode = '404'
    out = av.vt_lookup_hash('b'*64, client=client)
    assert out['verdict'] == 'unknown' and out.get('status') == 404
    # error branch
    client._mode = 'error'
    out = av.vt_lookup_hash('b'*64, client=client)
    assert out['ok'] is not True if 'ok' in out else out['verdict'] == 'unknown'


def test_malwarebazaar_lookup_variants(monkeypatch):
    import httpx

    class Resp:
        def __init__(self, code=200, data=None):
            self.status_code = code
            self._data = data or {}
        def raise_for_status(self):
            if self.status_code >= 400 and self.status_code != 404:
                raise httpx.HTTPError('boom')
        def json(self):
            return self._data

    class Client:
        def __init__(self, *a, **k):
            self.mode = 'ok'
        def post(self, url, data=None):
            if self.mode == 'ok-mal':
                return Resp(200, {"query_status": "ok", "data": [{"id":1}]})
            if self.mode == 'no-result':
                return Resp(200, {"query_status": "no_result"})
            if self.mode == '404':
                return Resp(404, {})
            if self.mode == 'error':
                return Resp(500, {})
            return Resp(200, {"query_status": "ok", "data": []})
        def close(self):
            return None

    client = Client()
    # malicious
    client.mode = 'ok-mal'
    out = av.malwarebazaar_lookup_hash('c'*64, client=client)
    assert out['verdict'] == 'malicious'
    # unknown via ok but empty
    client.mode = 'ok-empty'
    out = av.malwarebazaar_lookup_hash('c'*64, client=client)
    assert out['verdict'] == 'unknown'
    # no_result
    client.mode = 'no-result'
    out = av.malwarebazaar_lookup_hash('c'*64, client=client)
    assert out['verdict'] == 'unknown'
    # 404
    client.mode = '404'
    out = av.malwarebazaar_lookup_hash('c'*64, client=client)
    assert out['verdict'] == 'unknown' and out.get('status') == 404
    # error
    client.mode = 'error'
    out = av.malwarebazaar_lookup_hash('c'*64, client=client)
    assert out['verdict'] == 'unknown'


def test_teamcymru_dns_and_fallback(monkeypatch):
    # Inject dnspython shim
    pkg_dns = types.ModuleType('dns')
    resolv = types.ModuleType('dns.resolver')

    class Answer:
        def __iter__(self):
            return iter([types.SimpleNamespace(address='127.0.0.2')])
    class Resolver:
        def __init__(self):
            self.timeout = 0
            self.lifetime = 0
        def resolve(self, name, t):
            return Answer()

    resolv.Resolver = Resolver
    # set attribute on parent and register modules
    pkg_dns.resolver = resolv
    monkeypatch.setitem(sys.modules, 'dns', pkg_dns)
    monkeypatch.setitem(sys.modules, 'dns.resolver', resolv)

    monkeypatch.setenv('MHR_USE_DNSPYTHON', '1')
    out = av.teamcymru_mhr_lookup_hash('d'*64)
    assert out['verdict'] == 'malicious'

    # Change resolver to return non-malicious ip
    class Answer2:
        def __iter__(self):
            return iter([types.SimpleNamespace(address='127.0.0.1')])
    resolv2 = types.ModuleType('dns.resolver')
    resolv2.Resolver = Resolver
    def resolve_other(self, name, t):
        return Answer2()
    Resolver.resolve = resolve_other
    pkg_dns.resolver = resolv2
    monkeypatch.setitem(sys.modules, 'dns.resolver', resolv2)
    out = av.teamcymru_mhr_lookup_hash('e'*64)
    assert out['verdict'] == 'unknown' and out.get('ip') == '127.0.0.1'

    # Fallback via socket when MHR_USE_DNSPYTHON=0
    monkeypatch.setenv('MHR_USE_DNSPYTHON', '0')
    monkeypatch.setitem(sys.modules, 'dns.resolver', None)
    monkeypatch.setattr(av.socket, 'gethostbyname', lambda name: '127.0.0.2', raising=True)
    out = av.teamcymru_mhr_lookup_hash('f'*64)
    assert out['verdict'] == 'malicious'

    # Fallback error -> unknown
    monkeypatch.setattr(av.socket, 'gethostbyname', lambda name: (_ for _ in ()).throw(RuntimeError('dns fail')), raising=True)
    out = av.teamcymru_mhr_lookup_hash('f'*64)
    assert out['verdict'] == 'unknown'


def test_check_hash_writes_and_consolidates(monkeypatch):
    calls = []
    # Cache miss
    monkeypatch.setattr(av.db, 'get_hash_verdict', lambda **k: None, raising=True)
    def upsert(**k):
        calls.append((k['source'], k['verdict']))
    monkeypatch.setattr(av.db, 'upsert_hash_verdict', lambda **k: upsert(**k), raising=True)

    # Mock lookups
    monkeypatch.setenv('VT_API_KEY', 'dummy')
    monkeypatch.setattr(av, 'vt_lookup_hash', lambda h: {'source':'virustotal','verdict':'suspicious'}, raising=True)
    monkeypatch.setattr(av, 'malwarebazaar_lookup_hash', lambda h: {'source':'malwarebazaar','verdict':'malicious'}, raising=True)
    monkeypatch.setattr(av, 'teamcymru_mhr_lookup_hash', lambda h: {'source':'teamcymru','verdict':'unknown'}, raising=True)

    out = av.check_hash('g'*64, use_cloud=True, sources=("virustotal","malwarebazaar","teamcymru"))
    assert out['verdict'] == 'malicious'
    assert set(src for src,_ in calls) >= {"virustotal","malwarebazaar","teamcymru"}


def test_walk_files_limit_and_hash_files_error(tmp_path: Path):
    # build structure
    d = tmp_path / 'root'
    d.mkdir()
    f1 = d / 'a.txt'; f1.write_text('a')
    f2 = d / 'b.txt'; f2.write_text('b')
    # limit 1
    files = list(av._walk_files(d, recursive=True, limit=1))
    assert len(files) == 1
    # hash_files error: pass directory to trigger error entry
    out = av.hash_files([d])
    assert isinstance(out, list) and any('error' in item for item in out)


def test_throttle_sleep(monkeypatch):
    # control time
    t = {'now': 100.0, 'slept': 0.0}
    def fake_monotonic():
        return t['now']
    def fake_sleep(dt):
        t['slept'] += dt
        # increment now to simulate passage
        t['now'] += dt
    monkeypatch.setattr(av, '_MIN_INTERVAL', 0.1, raising=False)
    monkeypatch.setattr(av.time, 'monotonic', fake_monotonic, raising=True)
    monkeypatch.setattr(av.time, 'sleep', fake_sleep, raising=True)

    av._LAST_CALL.clear()
    av._throttle('x')  # first call, no sleep
    # immediate second call should sleep ~0.1
    av._throttle('x')
    assert t['slept'] >= 0.099
