from mcp_win_admin import system


def test_get_performance_snapshot_basic():
    snap = system.get_performance_snapshot()
    assert isinstance(snap.cpu_percent, float)
    assert 0.0 <= snap.cpu_percent <= 100.0
    assert isinstance(snap.mem_percent, float)
    assert 0.0 <= snap.mem_percent <= 100.0
    assert isinstance(snap.mem_total, int) and snap.mem_total > 0
    assert isinstance(snap.mem_used, int) and snap.mem_used >= 0
    assert isinstance(snap.disk_percent, float)
    assert 0.0 <= snap.disk_percent <= 100.0
    assert isinstance(snap.uptime_seconds, int) and snap.uptime_seconds >= 0
    assert isinstance(snap.processes_total, int) and snap.processes_total >= 0

    d = snap.to_dict()
    assert set(
        [
            "ts_iso",
            "cpu_percent",
            "mem_percent",
            "mem_total",
            "mem_used",
            "disk_percent",
            "uptime_seconds",
            "processes_total",
        ]
    ).issubset(d.keys())
