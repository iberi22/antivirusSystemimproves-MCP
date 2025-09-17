import types

import mcp_win_admin.system as system


def test_overall_disk_percent_handles_disk_usage_errors(monkeypatch):
    # Create a fake partition entry with fstype and mountpoint
    part = types.SimpleNamespace(fstype="NTFS", mountpoint="Z:/")
    monkeypatch.setattr(system.psutil, "disk_partitions", lambda all=False: [part])
    # Force disk_usage to raise so the except:continue branch is taken
    def boom(_mp):
        raise RuntimeError("no access")
    monkeypatch.setattr(system.psutil, "disk_usage", boom)

    val = system._overall_disk_percent()
    assert isinstance(val, float) and val == 0.0


def test_get_performance_snapshot_pids_exception(monkeypatch):
    # Make pids() raise to cover fallback path
    monkeypatch.setattr(system.psutil, "pids", lambda: (_ for _ in ()).throw(RuntimeError("x")))
    # Speed up cpu_percent to avoid delay
    monkeypatch.setattr(system.psutil, "cpu_percent", lambda interval=0.0: 0.0)
    # Also avoid touching real disk
    monkeypatch.setattr(system, "_overall_disk_percent", lambda: 0.0)

    snap = system.get_performance_snapshot()
    assert snap.processes_total == 0
