import os
from pathlib import Path
import pytest

from mcp_win_admin import av


def test_vt_lookup_internal_client_closes(monkeypatch):
    import httpx

    monkeypatch.setenv('VT_API_KEY', 'dummy')
    events = {'closed': False}

    class Resp:
        def __init__(self, code=404, data=None):
            self.status_code = code
            self._data = data or {}
        def raise_for_status(self):
            return None
        def json(self):
            return self._data

    class Client:
        def __init__(self, *a, **k):
            pass
        def get(self, url, headers=None):
            # force 404 path
            return Resp(404, {})
        def close(self):
            events['closed'] = True

    monkeypatch.setattr(httpx, 'Client', Client, raising=True)
    out = av.vt_lookup_hash('a'*64, client=None)
    assert out and out.get('status') == 404
    assert events['closed'] is True


def test_vt_lookup_internal_error_branch(monkeypatch):
    import httpx

    monkeypatch.setenv('VT_API_KEY', 'dummy')

    class Resp:
        def __init__(self):
            self.status_code = 500
        def raise_for_status(self):
            raise httpx.HTTPError('boom')

    class Client:
        def __init__(self, *a, **k):
            pass
        def get(self, url, headers=None):
            return Resp()
        def close(self):
            return None

    monkeypatch.setattr(httpx, 'Client', Client, raising=True)
    out = av.vt_lookup_hash('b'*64, client=None)
    assert out and out.get('verdict') == 'unknown' and 'error' in out


def test_malwarebazaar_internal_client_closes(monkeypatch):
    import httpx
    events = {'closed': False}

    class Resp:
        def __init__(self, code=200, data=None):
            self.status_code = code
            self._data = data or {}
        def raise_for_status(self):
            return None
        def json(self):
            return self._data

    class Client:
        def __init__(self, *a, **k):
            pass
        def post(self, url, data=None):
            return Resp(200, {"query_status": "no_result"})
        def close(self):
            events['closed'] = True

    import httpx
    monkeypatch.setattr(httpx, 'Client', Client, raising=True)
    out = av.malwarebazaar_lookup_hash('c'*64, client=None)
    assert out and out.get('verdict') == 'unknown'
    assert events['closed'] is True


def test_hash_file_unsupported_algo(tmp_path: Path):
    f = tmp_path / 'x.bin'
    f.write_bytes(b'1234')
    with pytest.raises(ValueError):
        av._hash_file(f, 'sha512')


def test_scan_path_recursive_with_limit(tmp_path: Path):
    base = tmp_path / 'dir'
    (base / 'a').mkdir(parents=True)
    (base / 'a' / 'f1.txt').write_text('1')
    (base / 'a' / 'f2.txt').write_text('2')
    (base / 'b').mkdir()
    (base / 'b' / 'f3.txt').write_text('3')
    (base / 'f4.txt').write_text('4')

    res = av.scan_path(str(base), recursive=True, limit=2, use_cloud=False)
    assert isinstance(res, list) and len(res) == 2
    for item in res:
        assert 'hash' in item and 'verdict' in item


def test_check_hash_cache_hit(monkeypatch):
    # cache returns clean, use_cloud False should not consult sources
    monkeypatch.setattr(av.db, 'get_hash_verdict', lambda **k: {"verdict": "clean"}, raising=True)
    out = av.check_hash('d'*64, use_cloud=False)
    assert out['verdict'] == 'clean'
