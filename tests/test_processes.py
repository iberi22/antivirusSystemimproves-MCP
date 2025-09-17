from mcp_win_admin import processes


def test_list_processes_default():
    items = processes.list_processes(limit=5, sort_by="memory")
    assert isinstance(items, list)
    assert 1 <= len(items) <= 5
    sample = items[0]
    assert "pid" in sample and isinstance(sample["pid"], int)
    assert "name" in sample and isinstance(sample["name"], str)
    # Campos pueden ser None dependiendo de permisos
    assert "cpu_percent" in sample
    assert "memory_rss" in sample


def test_list_processes_sort_cpu():
    items = processes.list_processes(limit=3, sort_by="cpu")
    assert isinstance(items, list)
    assert 1 <= len(items) <= 3


def test_list_processes_sort_pid():
    items = processes.list_processes(limit=3, sort_by="pid")
    assert isinstance(items, list)
    assert 1 <= len(items) <= 3
