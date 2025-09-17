import importlib
from pathlib import Path


def test_ip_per_source_cache_avoids_network(monkeypatch, tmp_path):
    db = importlib.import_module("mcp_win_admin.db")
    rep = importlib.import_module("mcp_win_admin.reputation")

    # Use a temp DB
    temp_db = tmp_path / "state.sqlite3"
    monkeypatch.setattr(db, "DEFAULT_DB_PATH", temp_db)
    db.init_db(temp_db)

    # Preload per-source cache for otx and greynoise
    db.upsert_ip_reputation_source(ip="1.2.3.4", source="otx", verdict="malicious", db_path=temp_db)
    db.upsert_ip_reputation_source(ip="1.2.3.4", source="greynoise", verdict="suspicious", db_path=temp_db)

    # Make network functions fail if called for these sources
    monkeypatch.setenv("REP_THROTTLE_MIN_INTERVAL", "0")
    monkeypatch.setattr(rep, "_otx_ip_lookup", lambda *a, **k: (_ for _ in ()).throw(AssertionError("otx should be cached")))
    monkeypatch.setattr(rep, "_greynoise_ip_lookup", lambda *a, **k: (_ for _ in ()).throw(AssertionError("greynoise should be cached")))
    # Allow abuseipdb to return a known value
    monkeypatch.setattr(rep, "_abuseipdb_ip_lookup", lambda ip, client=None: {"source": "abuseipdb", "verdict": "unknown", "score": 0})

    out = rep.check_ip("1.2.3.4", use_cloud=True, ttl_seconds=3600, sources=("otx", "greynoise", "abuseipdb"))
    assert out["verdict"] in {"malicious", "suspicious", "unknown"}
    # Ensure cached entries are present and marked
    srcs = {s["source"]: s for s in out["sources"]}
    assert srcs["otx"]["cached"] is True
    assert srcs["greynoise"]["cached"] is True
    assert srcs["abuseipdb"]["cached"] is not True  # fetched


essential_envs = {
    "OTX_API_KEY": "OTX",
    "GREYNOISE_API_KEY": "GreyNoise",
    "ABUSEIPDB_API_KEY": "AbuseIPDB",
}


def test_domain_per_source_cache_with_otx(monkeypatch, tmp_path):
    db = importlib.import_module("mcp_win_admin.db")
    rep = importlib.import_module("mcp_win_admin.reputation")

    temp_db = tmp_path / "state.sqlite3"
    monkeypatch.setattr(db, "DEFAULT_DB_PATH", temp_db)
    db.init_db(temp_db)

    db.upsert_domain_reputation_source(domain="example.com", source="otx", verdict="malicious", db_path=temp_db)

    monkeypatch.setenv("REP_THROTTLE_MIN_INTERVAL", "0")
    # Network must not be called for OTX
    monkeypatch.setattr(rep, "_otx_domain_lookup", lambda *a, **k: (_ for _ in ()).throw(AssertionError("otx should be cached")))

    out = rep.check_domain("example.com", use_cloud=True, ttl_seconds=3600, sources=("otx",))
    assert out["verdict"] in {"malicious", "suspicious", "unknown"}
    srcs = {s["source"]: s for s in out["sources"]}
    assert srcs["otx"]["cached"] is True
