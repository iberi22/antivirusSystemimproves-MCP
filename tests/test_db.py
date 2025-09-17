from pathlib import Path

from mcp_win_admin import db


def test_db_init_and_snapshot(tmp_path: Path):
    db_path = tmp_path / "state.sqlite3"

    # Init DB
    db.init_db(db_path)

    # Insert snapshot
    snap = {
        "cpu_percent": 1.0,
        "mem_percent": 2.0,
        "mem_total": 3,
        "mem_used": 2,
        "disk_percent": 4.0,
        "uptime_seconds": 5,
        "processes_total": 6,
    }
    row_id = db.insert_snapshot(snap, db_path)
    assert isinstance(row_id, int) and row_id > 0

    # Read back last snapshot
    last = db.get_last_snapshot(db_path)
    assert last is not None
    assert last["cpu_percent"] == snap["cpu_percent"]
    assert last["processes_total"] == snap["processes_total"]


def test_db_log_event(tmp_path: Path):
    db_path = tmp_path / "state.sqlite3"
    db.init_db(db_path)

    eid = db.log_event("info", "mensaje", code="TST", db_path=db_path)
    assert isinstance(eid, int) and eid > 0
