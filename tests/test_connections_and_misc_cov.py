import types
import pytest

from mcp_win_admin import av
from mcp_win_admin import config as cfg
from mcp_win_admin import connections as conns


def test_hash_files_success_appends(tmp_path):
    f = tmp_path / 'x.bin'
    f.write_bytes(b'hello')
    out = av.hash_files([f], algos=("sha256", "md5"))
    assert isinstance(out, list) and len(out) == 1
    item = out[0]
    assert 'sha256' in item and 'md5' in item and item['path'].endswith('x.bin')


def test_config_generic_cap_env(monkeypatch):
    # Set env so generic cap becomes max(50, value). With 20 it should keep 50.
    monkeypatch.setenv("MCP_GENERIC_MAX", "20")
    val = cfg.clamp_limit(10, "other")
    assert val == 10  # requested 10 under cap 50
    # Also test when requested is None, it should return cap 50
    val2 = cfg.clamp_limit(None, "other")
    assert val2 == 50


class Conn:
    def __init__(self, fd, family, type_, laddr, raddr, status, pid):
        self.fd = fd
        self.family = family
        self.type = type_
        self.laddr = laddr
        self.raddr = raddr
        self.status = status
        self.pid = pid


class Addr:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port


class Fam:
    def __init__(self, v):
        self.value = v


def test_connections_basic_and_limit(monkeypatch):
    import psutil

    c1 = Conn(1, Fam(2), Fam(3), Addr('127.0.0.1', 80), None, psutil.CONN_LISTEN, 123)
    c2 = Conn(2, Fam(2), Fam(3), Addr('127.0.0.1', 81), Addr('1.2.3.4', 5000), 'ESTABLISHED', 0)
    c3 = Conn(3, Fam(2), Fam(3), None, None, psutil.CONN_LISTEN, 456)

    def fake_net_connections(kind='inet'):
        return [c1, c2, c3]

    class P:
        def __init__(self, pid):
            self._pid = pid
        def name(self):
            return f"proc{self._pid}"

    monkeypatch.setattr(conns.psutil, 'net_connections', fake_net_connections, raising=True)
    monkeypatch.setattr(conns.psutil, 'Process', P, raising=True)
    # limit=2 should break after two appends
    out = conns.list_connections(limit=2, include_process=True)
    assert len(out) == 2
    assert out[0]['process_name'] == 'proc123'


def test_connections_listening_filter_and_proc_exception(monkeypatch):
    import psutil

    c1 = Conn(1, Fam(2), Fam(3), Addr('127.0.0.1', 80), None, 'CLOSE_WAIT', 789)
    c2 = Conn(2, Fam(2), Fam(3), Addr('127.0.0.1', 81), None, psutil.CONN_LISTEN, 999)

    def fake_net_connections(kind='inet'):
        return [c1, c2]

    def bad_process(pid):
        raise RuntimeError('access denied')

    monkeypatch.setattr(conns.psutil, 'net_connections', fake_net_connections, raising=True)
    monkeypatch.setattr(conns.psutil, 'Process', bad_process, raising=True)
    out = conns.list_connections(listening_only=True, include_process=True)
    # Only c2 should pass the filter; process_name should be None due to exception
    assert len(out) == 1 and out[0]['status'] == psutil.CONN_LISTEN and out[0].get('process_name') is None


def test_connections_global_exception(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError('psutil fail')
    monkeypatch.setattr(conns.psutil, 'net_connections', boom, raising=True)
    out = conns.list_connections()
    assert isinstance(out, list) and out and 'error' in out[0]


def test_connections_inner_except_continue(monkeypatch):
    # Create a connection whose laddr raises on attribute access to hit inner except branch
    import psutil

    class BadAddr:
        def __getattr__(self, name):
            raise RuntimeError('addr broken')

    class ConnBad:
        def __init__(self):
            self.fd = 1
            self.family = type('F', (), {'value': 2})()
            self.type = type('T', (), {'value': 3})()
            self.laddr = BadAddr()
            self.raddr = None
            self.status = psutil.CONN_LISTEN
            self.pid = 0

    def fake_net_connections(kind='inet'):
        return [ConnBad()]

    monkeypatch.setattr(conns.psutil, 'net_connections', fake_net_connections, raising=True)
    out = conns.list_connections()
    # The bad row should be skipped due to inner except, resulting in empty list
    assert out == []
