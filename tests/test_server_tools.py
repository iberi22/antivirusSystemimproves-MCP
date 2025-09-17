from mcp_win_admin.server import (
    system_scan_performance,
    processes_list,
    profiles_list,
    profiles_preview,
)


def test_system_scan_performance_no_persist():
    res = system_scan_performance(persist=False)
    assert isinstance(res, dict)
    assert "snapshot" in res
    snap = res["snapshot"]
    assert isinstance(snap, dict)
    assert "cpu_percent" in snap and 0.0 <= float(snap["cpu_percent"]) <= 100.0
    assert res.get("persisted_id") is None


def test_processes_list_basic():
    items = processes_list(limit=3, sort_by="memory")
    assert isinstance(items, list)
    assert 1 <= len(items) <= 3


def test_profiles_list_and_preview():
    lst = profiles_list()
    assert isinstance(lst, list)
    assert len(lst) >= 1
    # Usa el primer perfil para preview
    name = lst[0]["name"]
    prev = profiles_preview(name)
    assert isinstance(prev, dict)
    assert prev.get("name") == name
