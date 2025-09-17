import builtins
import importlib
from types import SimpleNamespace

import pytest


def test_teamcymru_malicious(monkeypatch):
    monkeypatch.setenv("MHR_USE_DNSPYTHON", "0")
    av = importlib.import_module("mcp_win_admin.av")

    def fake_gethostbyname(name):
        return "127.0.0.2"

    monkeypatch.setattr(av.socket, "gethostbyname", fake_gethostbyname)
    res = av.teamcymru_mhr_lookup_hash("d41d8cd98f00b204e9800998ecf8427e")
    assert res["verdict"] == "malicious"


def test_teamcymru_unknown(monkeypatch):
    monkeypatch.setenv("MHR_USE_DNSPYTHON", "0")
    av = importlib.import_module("mcp_win_admin.av")

    def fake_gethostbyname(name):
        return "127.0.0.1"

    monkeypatch.setattr(av.socket, "gethostbyname", fake_gethostbyname)
    res = av.teamcymru_mhr_lookup_hash("d41d8cd98f00b204e9800998ecf8427e")
    assert res["verdict"] == "unknown"


def test_check_hash_uses_teamcymru(monkeypatch):
    monkeypatch.setenv("MHR_USE_DNSPYTHON", "0")
    av = importlib.import_module("mcp_win_admin.av")

    def fake_tc(hash_hex):
        return {"source": "teamcymru", "verdict": "malicious"}

    monkeypatch.setattr(av, "teamcymru_mhr_lookup_hash", fake_tc)
    out = av.check_hash("abcd", algo="md5", use_cloud=True, sources=("teamcymru",), ttl_seconds=None)
    assert out["verdict"] == "malicious"
    assert any(s.get("source") == "teamcymru" for s in out.get("sources", []))


def test_scan_path_without_cloud(monkeypatch, tmp_path):
    av = importlib.import_module("mcp_win_admin.av")
    # archivo temporal
    p = tmp_path / "x.bin"
    p.write_bytes(b"hello")

    # Stub check_hash to avoid network
    def fake_check_hash(h, **kwargs):
        return {"verdict": "unknown"}

    monkeypatch.setattr(av, "check_hash", fake_check_hash)
    res = av.scan_path(str(tmp_path), recursive=False, limit=10, algo="md5", use_cloud=False)
    assert isinstance(res, list)
    assert any(item.get("path", "").endswith("x.bin") for item in res)
