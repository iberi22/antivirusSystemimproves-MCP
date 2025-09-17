import importlib


def test_check_ip_with_new_sources(monkeypatch):
    rep = importlib.import_module("mcp_win_admin.reputation")
    # Evitar sleeps en tests
    monkeypatch.setenv("REP_THROTTLE_MIN_INTERVAL", "0")

    # Parchear lookups para evitar red
    monkeypatch.setattr(rep, "_otx_ip_lookup", lambda ip, client=None: {"source": "otx", "verdict": "malicious", "pulses": 3})
    monkeypatch.setattr(rep, "_greynoise_ip_lookup", lambda ip, client=None: {"source": "greynoise", "verdict": "suspicious", "noise": True, "riot": False})
    monkeypatch.setattr(rep, "_abuseipdb_ip_lookup", lambda ip, client=None: {"source": "abuseipdb", "verdict": "unknown", "score": 0})

    out = rep.check_ip("1.2.3.4", use_cloud=True, ttl_seconds=None, sources=("otx", "greynoise", "abuseipdb"))
    assert out["verdict"] == "malicious"
    assert len(out["sources"]) == 3


def test_check_domain_with_otx(monkeypatch):
    rep = importlib.import_module("mcp_win_admin.reputation")
    monkeypatch.setenv("REP_THROTTLE_MIN_INTERVAL", "0")
    monkeypatch.setattr(rep, "_otx_domain_lookup", lambda domain, client=None: {"source": "otx", "verdict": "malicious", "pulses": 1})

    out = rep.check_domain("example.com", use_cloud=True, ttl_seconds=None, sources=("otx",))
    assert out["verdict"] == "malicious"
