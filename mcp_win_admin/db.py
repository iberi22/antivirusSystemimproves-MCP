import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional


DEFAULT_DB_DIR = Path.home() / ".mcp_win_admin"
DEFAULT_DB_PATH = DEFAULT_DB_DIR / "state.sqlite3"


def _ensure_db_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _connect(db_path: Path) -> sqlite3.Connection:
    _ensure_db_dir(db_path)
    conn = sqlite3.connect(db_path, timeout=10, isolation_level=None)
    # Enable WAL for better concurrency and durability
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    # Light, safe defaults for performance
    # NORMAL reduces fsync overhead vs FULL while keeping durability acceptable in WAL
    conn.execute("PRAGMA synchronous=NORMAL;")
    # Prefer in-memory temporary storage to reduce disk churn
    conn.execute("PRAGMA temp_store=MEMORY;")
    # Limit analysis work and enable optimizer improvements later via optimize_db()
    conn.execute("PRAGMA analysis_limit=400;")
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def get_conn(db_path: Optional[Path] = None) -> Iterable[sqlite3.Connection]:
    """Context manager for DB connection with WAL mode enabled."""
    path = db_path or DEFAULT_DB_PATH
    conn = _connect(path)
    try:
        yield conn
    finally:
        conn.close()


def init_db(db_path: Optional[Path] = None) -> None:
    with get_conn(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY,
                ts_utc TEXT NOT NULL,
                cpu_percent REAL NOT NULL,
                mem_percent REAL NOT NULL,
                mem_total BIGINT NOT NULL,
                mem_used BIGINT NOT NULL,
                disk_percent REAL NOT NULL,
                uptime_seconds BIGINT NOT NULL,
                processes_total INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_snapshots_ts ON snapshots(ts_utc);

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY,
                ts_utc TEXT NOT NULL,
                level TEXT NOT NULL,
                code TEXT,
                message TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_utc);

            -- Antivirus hash verdict cache
            CREATE TABLE IF NOT EXISTS av_hash_verdicts (
                hash TEXT NOT NULL,
                algo TEXT NOT NULL,
                source TEXT NOT NULL,
                verdict TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                metadata TEXT,
                PRIMARY KEY (hash, algo, source)
            );

            CREATE INDEX IF NOT EXISTS idx_av_hash ON av_hash_verdicts(hash);
            CREATE INDEX IF NOT EXISTS idx_av_last_seen ON av_hash_verdicts(last_seen);

            -- File integrity monitoring
            CREATE TABLE IF NOT EXISTS integrity_baselines (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                root_path TEXT NOT NULL,
                algo TEXT NOT NULL,
                created_ts TEXT NOT NULL
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_integrity_baselines_name ON integrity_baselines(name);

            CREATE TABLE IF NOT EXISTS integrity_files (
                baseline_id INTEGER NOT NULL,
                path TEXT NOT NULL,
                hash TEXT NOT NULL,
                size BIGINT,
                mtime REAL,
                PRIMARY KEY (baseline_id, path),
                FOREIGN KEY (baseline_id) REFERENCES integrity_baselines(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_integrity_files_baseline ON integrity_files(baseline_id);

            -- Reputation cache for IPs and domains
            CREATE TABLE IF NOT EXISTS reputation_ip (
                ip TEXT PRIMARY KEY,
                verdict TEXT NOT NULL,
                source TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                metadata TEXT
            );

            CREATE TABLE IF NOT EXISTS reputation_domain (
                domain TEXT PRIMARY KEY,
                verdict TEXT NOT NULL,
                source TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                metadata TEXT
            );
            """
        )
        # Per-source reputation caches (non-breaking addition)
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS reputation_ip_src (
                ip TEXT NOT NULL,
                source TEXT NOT NULL,
                verdict TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                metadata TEXT,
                PRIMARY KEY (ip, source)
            );

            CREATE TABLE IF NOT EXISTS reputation_domain_src (
                domain TEXT NOT NULL,
                source TEXT NOT NULL,
                verdict TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                metadata TEXT,
                PRIMARY KEY (domain, source)
            );
            """
        )
        # Helpful indexes for maintenance/TTL purges and reporting
        conn.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_rep_ip_last_seen ON reputation_ip(last_seen);
            CREATE INDEX IF NOT EXISTS idx_rep_domain_last_seen ON reputation_domain(last_seen);
            CREATE INDEX IF NOT EXISTS idx_rep_ip_src_last_seen ON reputation_ip_src(last_seen);
            CREATE INDEX IF NOT EXISTS idx_rep_domain_src_last_seen ON reputation_domain_src(last_seen);
            """
        )

        # Run optimizer pass at init (cheap, safe)
        try:
            conn.execute("PRAGMA optimize;")
        except Exception:
            pass


def insert_snapshot(data: Dict[str, Any], db_path: Optional[Path] = None) -> int:
    """Insert a system snapshot and return its row id.

    Expected keys: cpu_percent, mem_percent, mem_total, mem_used, disk_percent, uptime_seconds,
    processes_total
    """
    now = datetime.now(timezone.utc).isoformat()
    with get_conn(db_path) as conn:
        cur = conn.execute(
            """
            INSERT INTO snapshots (
                ts_utc, cpu_percent, mem_percent, mem_total, mem_used, disk_percent,
                uptime_seconds, processes_total
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now,
                float(data.get("cpu_percent", 0.0)),
                float(data.get("mem_percent", 0.0)),
                int(data.get("mem_total", 0)),
                int(data.get("mem_used", 0)),
                float(data.get("disk_percent", 0.0)),
                int(data.get("uptime_seconds", 0)),
                int(data.get("processes_total", 0)),
            ),
        )
        return int(cur.lastrowid)


def get_last_snapshot(db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM snapshots ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None


from . import events as evtmod

def log_event(level: str, message: str, code: Optional[str] = None, db_path: Optional[Path] = None) -> int:
    now = datetime.now(timezone.utc).isoformat()
    with get_conn(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO events (ts_utc, level, code, message) VALUES (?, ?, ?, ?)",
            (now, level.upper(), code, message),
        )
        try:
            evtmod.log_event_to_windows("MCP-Windows-Admin", 1000, strings=[message])
        except Exception:
            pass # No queremos que un fallo de log detenga la app
        return int(cur.lastrowid)


def upsert_hash_verdict(
    *,
    hash_hex: str,
    algo: str,
    verdict: str,
    source: str,
    metadata: Optional[str] = None,
    db_path: Optional[Path] = None,
) -> None:
    """Upsert a verdict for a file hash from a given source.

    verdict: e.g., 'malicious' | 'suspicious' | 'clean' | 'unknown'
    """
    now = datetime.now(timezone.utc).isoformat()
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO av_hash_verdicts (hash, algo, source, verdict, first_seen, last_seen, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hash, algo, source) DO UPDATE SET
                verdict=excluded.verdict,
                last_seen=excluded.last_seen,
                metadata=excluded.metadata
            """,
            (hash_hex.lower(), algo.lower(), source, verdict, now, now, metadata),
        )


def get_hash_verdict(
    *, hash_hex: str, algo: str, db_path: Optional[Path] = None, ttl_seconds: Optional[int] = None
) -> Optional[Dict[str, Any]]:
    """Return the strongest cached verdict for the given hash (if any).

    Prefers malicious > suspicious > clean > unknown when multiple sources exist.
    """
    order = {"malicious": 3, "suspicious": 2, "clean": 1, "unknown": 0}
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM av_hash_verdicts WHERE hash = ? AND algo = ?",
            (hash_hex.lower(), algo.lower()),
        ).fetchall()
        if not rows:
            return None
        if ttl_seconds is not None and ttl_seconds >= 0:
            try:
                cutoff = datetime.now(timezone.utc).timestamp() - int(ttl_seconds)
                fresh_rows = []
                for r in rows:
                    # last_seen is ISO; parse conservatively
                    try:
                        dt = datetime.fromisoformat(r["last_seen"])  # type: ignore[index]
                        ts = dt.timestamp()
                    except Exception:
                        ts = 0
                    if ts >= cutoff:
                        fresh_rows.append(r)
                rows = fresh_rows or rows  # if none fresh, keep originals to allow fallback
            except Exception:
                pass
        best = max(rows, key=lambda r: order.get(r["verdict"].lower(), -1))
        return dict(best)


def insert_integrity_baseline(*, name: str, root_path: str, algo: str, db_path: Optional[Path] = None) -> int:
    now = datetime.now(timezone.utc).isoformat()
    with get_conn(db_path) as conn:
        cur = conn.execute(
            """
            INSERT INTO integrity_baselines (name, root_path, algo, created_ts)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                root_path = excluded.root_path,
                algo = excluded.algo,
                created_ts = excluded.created_ts
            """,
            (name, root_path, algo.lower(), now),
        )
        # Retrieve id
        row = conn.execute("SELECT id FROM integrity_baselines WHERE name = ?", (name,)).fetchone()
        return int(row["id"]) if row else int(cur.lastrowid)


def insert_integrity_files_batch(*, baseline_id: int, items: Iterable[Dict[str, Any]], db_path: Optional[Path] = None) -> None:
    with get_conn(db_path) as conn:
        conn.executemany(
            """
            INSERT INTO integrity_files (baseline_id, path, hash, size, mtime)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(baseline_id, path) DO UPDATE SET
                hash = excluded.hash,
                size = excluded.size,
                mtime = excluded.mtime
            """,
            [
                (baseline_id, it.get("path"), it.get("hash"), it.get("size"), it.get("mtime"))
                for it in items
            ],
        )


def get_integrity_baseline_by_name(name: str, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM integrity_baselines WHERE name = ?",
            (name,),
        ).fetchone()
        return dict(row) if row else None


def list_integrity_baselines(db_path: Optional[Path] = None) -> list[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        rows = conn.execute("SELECT * FROM integrity_baselines ORDER BY created_ts DESC").fetchall()
        return [dict(r) for r in rows]


def list_events(limit: int = 1000, db_path: Optional[Path] = None) -> list[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
        return [dict(r) for r in rows]


def get_integrity_files(baseline_id: int, db_path: Optional[Path] = None) -> list[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM integrity_files WHERE baseline_id = ?",
            (baseline_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def upsert_ip_reputation(*, ip: str, verdict: str, source: str, metadata: Optional[str] = None, db_path: Optional[Path] = None) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO reputation_ip (ip, verdict, source, first_seen, last_seen, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                verdict = excluded.verdict,
                source = excluded.source,
                last_seen = excluded.last_seen,
                metadata = excluded.metadata
            """,
            (ip, verdict, source, now, now, metadata),
        )


def get_ip_reputation(*, ip: str, db_path: Optional[Path] = None, ttl_seconds: Optional[int] = None) -> Optional[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        row = conn.execute("SELECT * FROM reputation_ip WHERE ip = ?", (ip,)).fetchone()
        if not row:
            return None
        if ttl_seconds is not None and ttl_seconds >= 0:
            try:
                cutoff = datetime.now(timezone.utc).timestamp() - int(ttl_seconds)
                try:
                    dt = datetime.fromisoformat(row["last_seen"])  # type: ignore[index]
                    ts = dt.timestamp()
                except Exception:
                    ts = 0
                if ts < cutoff:
                    return None
            except Exception:
                pass
        return dict(row)


def upsert_ip_reputation_source(*, ip: str, source: str, verdict: str, metadata: Optional[str] = None, db_path: Optional[Path] = None) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO reputation_ip_src (ip, source, verdict, first_seen, last_seen, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip, source) DO UPDATE SET
                verdict = excluded.verdict,
                last_seen = excluded.last_seen,
                metadata = excluded.metadata
            """,
            (ip, source, verdict, now, now, metadata),
        )


def get_ip_reputation_sources(*, ip: str, db_path: Optional[Path] = None, ttl_seconds: Optional[int] = None) -> list[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        rows = conn.execute("SELECT * FROM reputation_ip_src WHERE ip = ?", (ip,)).fetchall()
        out: list[Dict[str, Any]] = []
        for row in rows:
            if ttl_seconds is not None and ttl_seconds >= 0:
                try:
                    cutoff = datetime.now(timezone.utc).timestamp() - int(ttl_seconds)
                    try:
                        dt = datetime.fromisoformat(row["last_seen"])  # type: ignore[index]
                        ts = dt.timestamp()
                    except Exception:
                        ts = 0
                    if ts < cutoff:
                        continue
                except Exception:
                    pass
            out.append(dict(row))
        return out


def upsert_domain_reputation_source(*, domain: str, source: str, verdict: str, metadata: Optional[str] = None, db_path: Optional[Path] = None) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO reputation_domain_src (domain, source, verdict, first_seen, last_seen, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain, source) DO UPDATE SET
                verdict = excluded.verdict,
                last_seen = excluded.last_seen,
                metadata = excluded.metadata
            """,
            (domain.lower(), source, verdict, now, now, metadata),
        )


def get_domain_reputation_sources(*, domain: str, db_path: Optional[Path] = None, ttl_seconds: Optional[int] = None) -> list[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        rows = conn.execute("SELECT * FROM reputation_domain_src WHERE domain = ?", (domain.lower(),)).fetchall()
        out: list[Dict[str, Any]] = []
        for row in rows:
            if ttl_seconds is not None and ttl_seconds >= 0:
                try:
                    cutoff = datetime.now(timezone.utc).timestamp() - int(ttl_seconds)
                    try:
                        dt = datetime.fromisoformat(row["last_seen"])  # type: ignore[index]
                        ts = dt.timestamp()
                    except Exception:
                        ts = 0
                    if ts < cutoff:
                        continue
                except Exception:
                    pass
            out.append(dict(row))
        return out


def upsert_domain_reputation(*, domain: str, verdict: str, source: str, metadata: Optional[str] = None, db_path: Optional[Path] = None) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO reputation_domain (domain, verdict, source, first_seen, last_seen, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                verdict = excluded.verdict,
                source = excluded.source,
                last_seen = excluded.last_seen,
                metadata = excluded.metadata
            """,
            (domain.lower(), verdict, source, now, now, metadata),
        )


def get_domain_reputation(*, domain: str, db_path: Optional[Path] = None, ttl_seconds: Optional[int] = None) -> Optional[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        row = conn.execute("SELECT * FROM reputation_domain WHERE domain = ?", (domain.lower(),)).fetchone()
        if not row:
            return None
        if ttl_seconds is not None and ttl_seconds >= 0:
            try:
                cutoff = datetime.now(timezone.utc).timestamp() - int(ttl_seconds)
                try:
                    dt = datetime.fromisoformat(row["last_seen"])  # type: ignore[index]
                    ts = dt.timestamp()
                except Exception:
                    ts = 0
                if ts < cutoff:
                    return None
            except Exception:
                pass
        return dict(row)


def purge_events_older_than(ttl_seconds: int, db_path: Optional[Path] = None) -> int:
    """Elimina eventos más antiguos que ttl_seconds. Retorna filas afectadas.

    Si ttl_seconds < 0, no hace nada y retorna 0.
    """
    if ttl_seconds is None or int(ttl_seconds) < 0:
        return 0
    cutoff_ts = datetime.now(timezone.utc).timestamp() - int(ttl_seconds)
    cutoff_iso = datetime.fromtimestamp(cutoff_ts, tz=timezone.utc).isoformat()
    with get_conn(db_path) as conn:
        cur = conn.execute("DELETE FROM events WHERE ts_utc < ?", (cutoff_iso,))
        return int(cur.rowcount if cur.rowcount is not None else 0)


def purge_reputation_older_than(ttl_seconds: int, db_path: Optional[Path] = None) -> Dict[str, int]:
    """Elimina reputación antigua (global y por fuente) basada en last_seen. Retorna conteos por tabla.

    Si ttl_seconds < 0, no hace nada.
    """
    counts = {"reputation_ip": 0, "reputation_domain": 0, "reputation_ip_src": 0, "reputation_domain_src": 0}
    if ttl_seconds is None or int(ttl_seconds) < 0:
        return counts
    cutoff_ts = datetime.now(timezone.utc).timestamp() - int(ttl_seconds)
    cutoff_iso = datetime.fromtimestamp(cutoff_ts, tz=timezone.utc).isoformat()
    with get_conn(db_path) as conn:
        for table in ("reputation_ip", "reputation_domain", "reputation_ip_src", "reputation_domain_src"):
            cur = conn.execute(f"DELETE FROM {table} WHERE last_seen < ?", (cutoff_iso,))
            counts[table] = int(cur.rowcount if cur.rowcount is not None else 0)
    return counts


def purge_av_hash_verdicts_older_than(ttl_seconds: int, db_path: Optional[Path] = None) -> int:
    """Elimina veredictos de hash antiguos basados en last_seen. Retorna filas afectadas.

    Si ttl_seconds < 0, no hace nada.
    """
    if ttl_seconds is None or int(ttl_seconds) < 0:
        return 0
    cutoff_ts = datetime.now(timezone.utc).timestamp() - int(ttl_seconds)
    cutoff_iso = datetime.fromtimestamp(cutoff_ts, tz=timezone.utc).isoformat()
    with get_conn(db_path) as conn:
        cur = conn.execute("DELETE FROM av_hash_verdicts WHERE last_seen < ?", (cutoff_iso,))
        return int(cur.rowcount if cur.rowcount is not None else 0)


def purge_old_data(
    *,
    events_ttl_seconds: Optional[int] = None,
    reputation_ttl_seconds: Optional[int] = None,
    hash_ttl_seconds: Optional[int] = None,
    db_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Ejecuta purgas de datos antiguos según TTLs dados. Retorna resumen.

    Cualquier TTL < 0 implica no purgar esa categoría.
    """
    summary: Dict[str, Any] = {"ok": True}
    try:
        summary["events_deleted"] = purge_events_older_than(events_ttl_seconds if events_ttl_seconds is not None else -1, db_path)
    except Exception as e:
        summary["events_error"] = str(e)
        summary["ok"] = False
    try:
        summary["reputation_deleted"] = purge_reputation_older_than(reputation_ttl_seconds if reputation_ttl_seconds is not None else -1, db_path)
    except Exception as e:
        summary["reputation_error"] = str(e)
        summary["ok"] = False
    try:
        summary["av_hash_deleted"] = purge_av_hash_verdicts_older_than(hash_ttl_seconds if hash_ttl_seconds is not None else -1, db_path)
    except Exception as e:
        summary["av_hash_error"] = str(e)
        summary["ok"] = False
    return summary


def optimize_db(db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Run lightweight SQLite optimizations and WAL checkpoint.

    Returns a dict with results and potential errors; safe to call periodically.
    """
    out: Dict[str, Any] = {"ok": True}
    with get_conn(db_path) as conn:
        try:
            # Let SQLite collect statistics and apply heuristics
            conn.execute("PRAGMA analysis_limit=400;")
            conn.execute("PRAGMA optimize;")
        except Exception as e:
            out["optimize_error"] = str(e)
            out["ok"] = False
        try:
            # Perform a passive WAL checkpoint to bound wal file size without blocking writers
            row = conn.execute("PRAGMA wal_checkpoint(PASSIVE);").fetchone()
            if row is not None:
                # returns (busy, log, checkpointed)
                out["wal_checkpoint"] = tuple(row)
        except Exception as e:
            out["wal_error"] = str(e)
            out["ok"] = False
    return out
