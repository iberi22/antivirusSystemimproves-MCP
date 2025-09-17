import sys
import types
import pytest

from mcp_win_admin import av
from mcp_win_admin import tasks


def test_av_throttle_initial_sleep(monkeypatch):
    t = {"now": 0.0}
    def mono():
        return t["now"]
    slept = {"s": 0.0}
    def sleep(d):
        slept["s"] += d
    monkeypatch.setattr(av, "_MIN_INTERVAL", 1.0, raising=False)
    monkeypatch.setattr(av, "time", types.SimpleNamespace(monotonic=mono, sleep=sleep))
    av._LAST_CALL["z"] = 0.0
    av._throttle("z")
    assert slept["s"] == pytest.approx(1.0, rel=1e-3)


def test_vt_lookup_404(monkeypatch):
    import httpx

    class Resp:
        def __init__(self):
            self.status_code = 404
        def raise_for_status(self):
            return None
        def json(self):
            return {}

    class Client:
        def __init__(self, *a, **k):
            pass
        def get(self, *a, **k):
            return Resp()
        def close(self):
            pass

    monkeypatch.setenv("VT_API_KEY", "k")
    monkeypatch.setattr(httpx, "Client", Client, raising=True)
    out = av.vt_lookup_hash("f"*64, client=None)
    assert out and out.get("verdict") == "unknown" and out.get("status") == 404


def test_vt_lookup_exception_with_provided_client(monkeypatch):
    class Client:
        def __init__(self):
            self.closed = False
        def get(self, *a, **k):
            raise RuntimeError("net down")
        def close(self):
            self.closed = True
    monkeypatch.setenv("VT_API_KEY", "k")
    c = Client()
    out = av.vt_lookup_hash("f"*64, client=c)
    assert out and out.get("verdict") == "unknown" and "error" in out
    # Provided client must not be force-closed by the function
    assert c.closed is False


def test_malwarebazaar_ok_and_unknown(monkeypatch):
    import httpx
    calls = {"mode": "ok"}

    class Resp:
        def __init__(self, mode):
            self.status_code = 200
            self._mode = mode
        def raise_for_status(self):
            return None
        def json(self):
            if self._mode == "ok":
                return {"query_status": "ok", "data": [{}, {}]}
            return {"query_status": "hash_not_found"}

    class Client:
        def __init__(self, *a, **k):
            pass
        def post(self, *a, **k):
            return Resp(calls["mode"])
        def close(self):
            pass

    monkeypatch.setattr(httpx, "Client", Client, raising=True)
    out = av.malwarebazaar_lookup_hash("f"*64, client=None)
    assert out and out.get("verdict") == "malicious" and out.get("count") == 2
    calls["mode"] = "nf"
    out2 = av.malwarebazaar_lookup_hash("f"*64, client=None)
    assert out2 and out2.get("verdict") == "unknown"


def test_teamcymru_dnspython_success(monkeypatch):
    # Provide fake dnspython with a Resolver that returns 127.0.0.2
    class R:
        timeout = 0
        lifetime = 0
        def resolve(self, name, qtype):
            class A:
                address = "127.0.0.2"
            return [A()]
    resolver_mod = types.SimpleNamespace(Resolver=lambda: R())
    dns_mod = types.SimpleNamespace(resolver=resolver_mod)
    monkeypatch.setenv("MHR_USE_DNSPYTHON", "1")
    monkeypatch.setitem(sys.modules, "dns", dns_mod)
    monkeypatch.setitem(sys.modules, "dns.resolver", resolver_mod)
    out = av.teamcymru_mhr_lookup_hash("a"*64)
    assert out["verdict"] == "malicious"


def test_teamcymru_dnspython_exception_then_socket(monkeypatch):
    # Fake dnspython present but raising; should hit except block (lines 154-155) then socket fallback
    class R:
        def __init__(self):
            self.timeout = 0
            self.lifetime = 0
        def resolve(self, name, qtype):
            raise RuntimeError("dns fail")
    resolver_mod = types.SimpleNamespace(Resolver=lambda: R())
    dns_mod = types.SimpleNamespace(resolver=resolver_mod)
    monkeypatch.setenv("MHR_USE_DNSPYTHON", "1")
    monkeypatch.setitem(sys.modules, "dns", dns_mod)
    monkeypatch.setitem(sys.modules, "dns.resolver", resolver_mod)
    import socket as pysocket
    monkeypatch.setattr(pysocket, "gethostbyname", lambda n: "127.0.0.1", raising=True)
    out = av.teamcymru_mhr_lookup_hash("b"*64)
    assert out["verdict"] == "unknown" and out.get("ip") == "127.0.0.1"


def test_teamcymru_outer_except_on_bad_timeout(monkeypatch):
    # Set invalid timeout to trigger ValueError at float(), caught by outer except
    monkeypatch.setenv("MHR_DNS_TIMEOUT", "bad")
    out = av.teamcymru_mhr_lookup_hash("c"*64)
    assert out["verdict"] == "unknown" and "error" in out


def test_tasks_state_filter_skips_all(monkeypatch):
    class Proc:
        def __init__(self, stdout: str):
            self.stdout = stdout
    headers = [
        "TaskName",
        "Next Run Time",
        "Status",
        "Last Run Time",
        "Author",
        "Task To Run",
    ]
    rows = [
        ["\\T1", "", "Ready", "", "u", "cmd 1"],
        ["\\T2", "", "Ready", "", "u", "cmd 2"],
    ]
    out = ",".join(headers) + "\n" + "\n".join(",".join(r) for r in rows)
    def fake_run(*a, **k):
        return Proc(out)
    monkeypatch.setattr(tasks.subprocess, "run", fake_run, raising=True)
    items = tasks.list_scheduled_tasks(limit=10, state="Disabled")
    assert items == []


def test_tasks_inner_exception_continue(monkeypatch):
    # Force per-row exception inside inner try so it continues and returns empty list
    class BadRow:
        def get(self, *a, **k):
            raise RuntimeError("bad row")
    class FakeReader:
        def __iter__(self):
            return iter([BadRow(), BadRow()])
    def make_reader(_):
        return FakeReader()
    class Proc:
        def __init__(self, stdout: str):
            self.stdout = stdout
    def fake_run(*a, **k):
        return Proc("dummy")
    monkeypatch.setattr(tasks.subprocess, "run", fake_run, raising=True)
    monkeypatch.setattr(tasks.csv, "DictReader", make_reader, raising=True)
    out = tasks.list_scheduled_tasks()
    assert out == []
