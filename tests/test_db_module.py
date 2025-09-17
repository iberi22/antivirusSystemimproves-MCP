import contextlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import mcp_win_admin.db as db


@pytest.fixture()
def tmp_db(tmp_path: Path):
    path = tmp_path / "state.sqlite3"
    db.init_db(path)
    return path


def test_snapshots_and_events(tmp_db: Path):
    # insert/get snapshot
    sid = db.insert_snapshot({
        "cpu_percent": 1.2,
        "mem_percent": 3.4,
        "mem_total": 100,
        "mem_used": 50,
        "disk_percent": 7.8,
        "uptime_seconds": 9,
        "processes_total": 10,
    }, tmp_db)
    assert isinstance(sid, int)
    last = db.get_last_snapshot(tmp_db)
    assert last and float(last["cpu_percent"]) == 1.2

    # log_event + purge_events_older_than
    db.log_event("INFO", "hello", db_path=tmp_db)
    db.log_event("INFO", "old", db_path=tmp_db)
    # Backdate one event to ensure purge works
    with db.get_conn(tmp_db) as conn:
        conn.execute(
            "UPDATE events SET ts_utc = ? WHERE message = ?",
            ((datetime.now(timezone.utc) - timedelta(days=10)).isoformat(), "old"),
        )
    assert db.purge_events_older_than(-1, tmp_db) == 0  # disabled
    purged = db.purge_events_older_than(60*60*24*7, tmp_db)  # 7 days
    assert purged >= 1


def test_hash_verdicts_and_ttls(tmp_db: Path):
    # upsert two sources and verify strongest verdict ordering and TTL freshness
    db.upsert_hash_verdict(hash_hex="aa", algo="sha256", verdict="clean", source="a", db_path=tmp_db)
    db.upsert_hash_verdict(hash_hex="aa", algo="sha256", verdict="malicious", source="b", db_path=tmp_db)
    best = db.get_hash_verdict(hash_hex="aa", algo="sha256", db_path=tmp_db)
    assert best and best["verdict"] == "malicious"
    # Fresh TTL path should collect rows into fresh_rows
    fresh = db.get_hash_verdict(hash_hex="aa", algo="sha256", db_path=tmp_db, ttl_seconds=10)
    assert fresh is not None

    # Make rows stale by backdating last_seen
    with db.get_conn(tmp_db) as conn:
        conn.execute(
            "UPDATE av_hash_verdicts SET last_seen = ?",
            ((datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),),
        )
    # TTL filter should keep originals as fallback if none fresh
    best2 = db.get_hash_verdict(hash_hex="aa", algo="sha256", db_path=tmp_db, ttl_seconds=10)
    assert best2 and best2["verdict"] in ("malicious", "clean")

    # Insert a broken row (unparseable last_seen) to cover exception path in TTL parse
    with db.get_conn(tmp_db) as conn:
        conn.execute("INSERT OR REPLACE INTO av_hash_verdicts (hash, algo, source, verdict, first_seen, last_seen) VALUES (?,?,?,?,?,?)",
                     ("aa", "sha256", "bad", "unknown", datetime.now(timezone.utc).isoformat(), "NOT-ISO"))
    best3 = db.get_hash_verdict(hash_hex="aa", algo="sha256", db_path=tmp_db, ttl_seconds=10)
    assert best3 is not None


def test_integrity_tables(tmp_db: Path, tmp_path: Path):
    # Create small baseline
    root = tmp_path / "files"
    root.mkdir()
    f = root / "a.txt"
    f.write_text("hello")
    bid = db.insert_integrity_baseline(name="base", root_path=str(root), algo="sha256", db_path=tmp_db)
    assert isinstance(bid, int)
    db.insert_integrity_files_batch(baseline_id=bid, items=[{"path": str(f.resolve()), "hash": "h", "size": 5, "mtime": 1.0}], db_path=tmp_db)
    row = db.get_integrity_baseline_by_name("base", db_path=tmp_db)
    assert row and row["name"] == "base"
    lst = db.list_integrity_baselines(tmp_db)
    assert any(r["name"] == "base" for r in lst)
    files = list(db.get_integrity_files(baseline_id=bid, db_path=tmp_db))
    assert files and files[0]["path"].endswith("a.txt")


def test_reputation_ip_and_domain_with_sources_and_ttl(tmp_db: Path):
    # IP reputation with sources table
    db.upsert_ip_reputation(ip="1.1.1.1", verdict="clean", source="a", db_path=tmp_db)
    db.upsert_ip_reputation_source(ip="1.1.1.1", source="a", verdict="clean", db_path=tmp_db)
    # Backdate source
    with db.get_conn(tmp_db) as conn:
        conn.execute(
            "UPDATE reputation_ip_src SET last_seen = ?",
            ((datetime.now(timezone.utc) - timedelta(days=5)).isoformat(),),
        )
    srcs = db.get_ip_reputation_sources(ip="1.1.1.1", db_path=tmp_db, ttl_seconds=60)
    # None fresh -> allow fallback to originals or empty list
    assert isinstance(srcs, list)

    # Domain reputation
    db.upsert_domain_reputation(domain="example.com", verdict="suspicious", source="x", db_path=tmp_db)
    db.upsert_domain_reputation_source(domain="example.com", source="x", verdict="suspicious", db_path=tmp_db)
    # Backdate both global and sources to enable purge later
    with db.get_conn(tmp_db) as conn:
        old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        conn.execute("UPDATE reputation_domain SET last_seen = ?", (old,))
        conn.execute("UPDATE reputation_domain_src SET last_seen = ?", (old,))

    # Purges
    counts = db.purge_reputation_older_than(-1, tmp_db)
    assert counts == {"reputation_ip": 0, "reputation_domain": 0, "reputation_ip_src": 0, "reputation_domain_src": 0}
    counts2 = db.purge_reputation_older_than(60*60*24*7, tmp_db)
    assert isinstance(counts2["reputation_domain"], int)

    # Also cover av hash purge
    n = db.purge_av_hash_verdicts_older_than(-1, tmp_db)
    assert n == 0
    n2 = db.purge_av_hash_verdicts_older_than(60, tmp_db)
    assert isinstance(n2, int)


def test_reputation_ttl_edge_cases(tmp_db: Path):
    class BadTTL:
        def __ge__(self, other):
            return True
        def __int__(self):
            raise ValueError("bad int")
    # IP source: bad ISO last_seen should hit inner parse except and be filtered with numeric TTL
    db.upsert_ip_reputation_source(ip="1.1.1.2", source="s1", verdict="clean", db_path=tmp_db)
    with db.get_conn(tmp_db) as conn:
        conn.execute("UPDATE reputation_ip_src SET last_seen = ? WHERE ip = ? AND source = ?", ("NOT-ISO", "1.1.1.2", "s1"))
    lst = db.get_ip_reputation_sources(ip="1.1.1.2", db_path=tmp_db, ttl_seconds=60)
    assert isinstance(lst, list) and len(lst) == 0
    # Outer try/except: non-int TTL should skip TTL filter and include the row
    lst2 = db.get_ip_reputation_sources(ip="1.1.1.2", db_path=tmp_db, ttl_seconds=BadTTL())
    assert any(r["source"] == "s1" for r in lst2)

    # Domain sources: same patterns
    db.upsert_domain_reputation_source(domain="example.org", source="s2", verdict="suspicious", db_path=tmp_db)
    with db.get_conn(tmp_db) as conn:
        conn.execute("UPDATE reputation_domain_src SET last_seen = ? WHERE domain = ? AND source = ?", ("NOT-ISO", "example.org", "s2"))
    dlst = db.get_domain_reputation_sources(domain="example.org", db_path=tmp_db, ttl_seconds=60)
    assert isinstance(dlst, list) and len(dlst) == 0
    dlst2 = db.get_domain_reputation_sources(domain="example.org", db_path=tmp_db, ttl_seconds=BadTTL())
    assert any(r["source"] == "s2" for r in dlst2)

    # Domain global: stale and bad-ISO + bad TTL
    db.upsert_domain_reputation(domain="stale.com", verdict="clean", source="s3", db_path=tmp_db)
    with db.get_conn(tmp_db) as conn:
        conn.execute("UPDATE reputation_domain SET last_seen = ? WHERE domain = ?", ((datetime.now(timezone.utc) - timedelta(days=30)).isoformat(), "stale.com"))
    assert db.get_domain_reputation(domain="stale.com", db_path=tmp_db, ttl_seconds=60) is None
    with db.get_conn(tmp_db) as conn:
        conn.execute("UPDATE reputation_domain SET last_seen = ? WHERE domain = ?", ("NOT-ISO", "stale.com"))
    # bad ISO -> ts=0 -> cutoff > 0 -> None
    assert db.get_domain_reputation(domain="stale.com", db_path=tmp_db, ttl_seconds=60) is None
    # non-int TTL -> outer except -> bypass TTL -> row present
    assert db.get_domain_reputation(domain="stale.com", db_path=tmp_db, ttl_seconds=BadTTL()) is not None


def test_purge_old_data_and_optimize_db(tmp_db: Path, monkeypatch: pytest.MonkeyPatch):
    # Happy path covering all three categories
    out = db.purge_old_data(events_ttl_seconds=0, reputation_ttl_seconds=0, hash_ttl_seconds=0, db_path=tmp_db)
    assert out["ok"] is True
    assert {"events_deleted", "reputation_deleted", "av_hash_deleted"}.issubset(out.keys())

    # Error paths: monkeypatch inner helpers to raise
    monkeypatch.setattr(db, "purge_events_older_than", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom ev")))
    monkeypatch.setattr(db, "purge_reputation_older_than", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom rep")))
    monkeypatch.setattr(db, "purge_av_hash_verdicts_older_than", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom av")))
    out2 = db.purge_old_data(events_ttl_seconds=0, reputation_ttl_seconds=0, hash_ttl_seconds=0, db_path=tmp_db)
    assert out2["ok"] is False
    assert "events_error" in out2 and "reputation_error" in out2 and "av_hash_error" in out2

    # optimize_db happy path
    ok = db.optimize_db(tmp_db)
    assert ok["ok"] is True

    # optimize_db error branches via fake connection
    class FakeConn:
        def __init__(self):
            self.calls = []
        def execute(self, sql, *args):
            self.calls.append(sql)
            if "PRAGMA optimize" in sql:
                raise RuntimeError("optimize error")
            if "PRAGMA wal_checkpoint" in sql:
                # Return a row-like iterable of 3 ints
                class Row(tuple):
                    pass
                return Row((0, 0, 0))
            return None
        def close(self):
            pass
    @contextlib.contextmanager
    def fake_get_conn(_path):
        yield FakeConn()
    monkeypatch.setattr(db, "get_conn", fake_get_conn)
    res = db.optimize_db(tmp_db)
    assert res["ok"] is False and ("optimize_error" in res or "wal_error" in res)


def test_list_events_and_ordering(tmp_db: Path):
    db.log_event("INFO", "a", db_path=tmp_db)
    db.log_event("INFO", "b", db_path=tmp_db)
    all_events = db.list_events(db_path=tmp_db)
    assert isinstance(all_events, list) and len(all_events) >= 2
    top1 = db.list_events(limit=1, db_path=tmp_db)
    assert len(top1) == 1


def test_ip_reputation_ttl_paths(tmp_db: Path):
    class BadTTL:
        def __ge__(self, other):
            return True
        def __int__(self):
            raise ValueError("bad int")
    ip = "2.2.2.2"
    db.upsert_ip_reputation(ip=ip, verdict="clean", source="src", db_path=tmp_db)
    # stale -> None
    with db.get_conn(tmp_db) as conn:
        conn.execute(
            "UPDATE reputation_ip SET last_seen = ? WHERE ip = ?",
            ((datetime.now(timezone.utc) - timedelta(days=30)).isoformat(), ip),
        )
    assert db.get_ip_reputation(ip=ip, db_path=tmp_db, ttl_seconds=60) is None
    # bad ISO -> ts=0 -> cutoff > 0 -> None
    with db.get_conn(tmp_db) as conn:
        conn.execute("UPDATE reputation_ip SET last_seen = ? WHERE ip = ?", ("NOT-ISO", ip))
    assert db.get_ip_reputation(ip=ip, db_path=tmp_db, ttl_seconds=60) is None
    # outer except on int(TTL) -> bypass TTL
    val = db.get_ip_reputation(ip=ip, db_path=tmp_db, ttl_seconds=BadTTL())
    assert isinstance(val, dict)


def test_get_hash_verdict_outer_ttl_exception(tmp_db: Path):
    class BadTTL:
        def __ge__(self, other):
            return True
        def __int__(self):
            raise ValueError("bad int")
    db.upsert_hash_verdict(hash_hex="bb", algo="sha256", verdict="clean", source="s", db_path=tmp_db)
    got = db.get_hash_verdict(hash_hex="bb", algo="sha256", db_path=tmp_db, ttl_seconds=BadTTL())
    assert got is not None


def test_init_db_optimize_exception(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    class FakeConn:
        def executescript(self, sql):
            return None
        def execute(self, sql):
            if "PRAGMA optimize" in sql:
                raise RuntimeError("fail optimize")
            return None
        def close(self):
            pass
    @contextlib.contextmanager
    def fake_get_conn(_path):
        yield FakeConn()
    monkeypatch.setattr(db, "get_conn", fake_get_conn)
    # Should not raise and cover except: pass
    db.init_db(tmp_path / "x.sqlite3")
