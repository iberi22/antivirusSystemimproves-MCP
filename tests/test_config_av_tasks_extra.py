import sys
import types
import io
import pytest

from mcp_win_admin import config as cfg
from mcp_win_admin import av
from mcp_win_admin import tasks


def test_config_parsers_and_defaults(monkeypatch):
    # Reset ENV and verify defaults (set/del explicitly)
    monkeypatch.delenv("MCP_LIGHT_MODE", raising=False)
    monkeypatch.delenv("MCP_PROC_LIST_MAX", raising=False)
    monkeypatch.delenv("MCP_CONN_LIST_MAX", raising=False)
    monkeypatch.delenv("MCP_EVENTS_MAX", raising=False)
    monkeypatch.delenv("MCP_WEBHOOK_TIMEOUT", raising=False)
    monkeypatch.delenv("MCP_ENABLE_ALERTS", raising=False)
    monkeypatch.delenv("MCP_FIREWALL_CMD_TIMEOUT", raising=False)
    monkeypatch.delenv("MCP_DEFAULT_REP_TTL", raising=False)

    # _get_bool true/false variants via env
    monkeypatch.setenv("MCP_LIGHT_MODE", "off")
    # Reload effect by monkeypatching directly
    monkeypatch.setattr(cfg, "LIGHT_MODE", cfg._get_bool("MCP_LIGHT_MODE", True), raising=True)
    assert cfg.LIGHT_MODE is False

    monkeypatch.setenv("MCP_ENABLE_ALERTS", "YES")
    monkeypatch.setattr(cfg, "ENABLE_ALERTS", cfg._get_bool("MCP_ENABLE_ALERTS", False), raising=True)
    assert cfg.ENABLE_ALERTS is True

    # int/float parsers
    monkeypatch.setenv("MCP_PROC_LIST_MAX", "123")
    monkeypatch.setattr(cfg, "PROC_LIST_MAX", cfg._get_int("MCP_PROC_LIST_MAX", 50), raising=True)
    assert cfg.PROC_LIST_MAX == 123

    monkeypatch.setenv("MCP_WEBHOOK_TIMEOUT", "2.5")
    monkeypatch.setattr(cfg, "WEBHOOK_TIMEOUT", cfg._get_float("MCP_WEBHOOK_TIMEOUT", 3.0), raising=True)
    assert abs(cfg.WEBHOOK_TIMEOUT - 2.5) < 1e-6

    # invalid values fallback
    monkeypatch.setenv("MCP_CONN_LIST_MAX", "bad")
    monkeypatch.setattr(cfg, "CONN_LIST_MAX", cfg._get_int("MCP_CONN_LIST_MAX", 200), raising=True)
    assert cfg.CONN_LIST_MAX == 200

    monkeypatch.setenv("MCP_FIREWALL_CMD_TIMEOUT", "bad")
    monkeypatch.setattr(cfg, "FIREWALL_CMD_TIMEOUT", cfg._get_float("MCP_FIREWALL_CMD_TIMEOUT", 5.0), raising=True)
    assert cfg.FIREWALL_CMD_TIMEOUT == 5.0


def test_config_clamp_and_effective_ttl(monkeypatch):
    # Clamp categories
    monkeypatch.setattr(cfg, "PROC_LIST_MAX", 10, raising=True)
    monkeypatch.setattr(cfg, "CONN_LIST_MAX", 5, raising=True)
    monkeypatch.setattr(cfg, "EVENTS_MAX", 7, raising=True)
    assert cfg.clamp_limit(None, "processes") == 10
    assert cfg.clamp_limit(3, "connections") == 3
    assert cfg.clamp_limit(999, "events") == 7

    # effective TTL with light mode toggle
    monkeypatch.setattr(cfg, "LIGHT_MODE", True, raising=True)
    monkeypatch.setattr(cfg, "DEFAULT_REP_TTL", 111, raising=True)
    assert cfg.effective_rep_ttl(None) == 111
    assert cfg.effective_rep_ttl(-1) == 111
    assert cfg.effective_rep_ttl(60) == 60
    monkeypatch.setattr(cfg, "LIGHT_MODE", False, raising=True)
    assert cfg.effective_rep_ttl(None) is None


def test_vt_lookup_unknown_branch(monkeypatch):
    import httpx

    class Resp:
        def __init__(self):
            self.status_code = 200
        def raise_for_status(self):
            return None
        def json(self):
            return {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}}}}

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
    assert out and out.get("verdict") == "unknown"


def test_check_hash_upsert_exceptions(monkeypatch):
    # Force db.upsert_hash_verdict to raise in all sources
    class DummyDB:
        def get_hash_verdict(self, **k):
            return None
        def upsert_hash_verdict(self, **k):
            raise RuntimeError("db locked")
    # Patch lookup functions to return fixed verdicts ensuring sources path is executed
    monkeypatch.setattr(av, "db", DummyDB(), raising=True)
    monkeypatch.setattr(av, "vt_lookup_hash", lambda h, client=None: {"source": "virustotal", "verdict": "clean"}, raising=True)
    monkeypatch.setattr(av, "malwarebazaar_lookup_hash", lambda h, client=None: {"source": "malwarebazaar", "verdict": "unknown"}, raising=True)
    monkeypatch.setattr(av, "teamcymru_mhr_lookup_hash", lambda h: {"source": "teamcymru", "verdict": "malicious"}, raising=True)
    res = av.check_hash("f"*64, use_cloud=True, sources=("virustotal", "malwarebazaar", "teamcymru"))
    # Should still consolidate verdict as 'malicious' ignoring upsert failures
    assert res["verdict"] == "malicious"


def test_tasks_decode_fallback_except_branch(monkeypatch):
    class Weird:
        def __bool__(self):
            return False  # triggers if not out
        def encode(self, *a, **k):
            raise RuntimeError("encode boom")
    class Proc:
        def __init__(self):
            self.stdout = Weird()
    def fake_run(*a, **k):
        return Proc()
    monkeypatch.setattr(tasks.subprocess, "run", fake_run, raising=True)
    out = tasks.list_scheduled_tasks()
    assert isinstance(out, list) and out and "error" in out[0]
