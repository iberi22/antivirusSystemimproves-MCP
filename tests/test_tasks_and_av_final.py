import types
import csv
import pytest

from mcp_win_admin import tasks
from mcp_win_admin import av


class Proc:
    def __init__(self, stdout: str):
        self.stdout = stdout


def test_tasks_success_state_and_limit(monkeypatch):
    # Build CSV with headers expected by parser
    headers = [
        "TaskName",
        "Next Run Time",
        "Status",
        "Last Run Time",
        "Author",
        "Task To Run",
    ]
    rows = [
        ["\\T1", "", "Ready", "", "u", "cmd.exe /c echo 1"],
        ["\\T2", "", "Running", "", "u", "cmd.exe /c echo 2"],
        ["\\T3", "", "Ready", "", "u", "cmd.exe /c echo 3"],
    ]
    out = ",".join(headers) + "\n" + "\n".join(",".join(r) for r in rows)

    def fake_run(*a, **k):
        return Proc(out)

    monkeypatch.setattr(tasks.subprocess, "run", fake_run, raising=True)

    # Filter by state 'Ready' and limit to 1 item
    items = tasks.list_scheduled_tasks(limit=1, state="Ready")
    assert len(items) == 1
    assert items[0]["TaskName"] == "\\T1"


def test_tasks_exception_returns_error(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("schtasks missing")
    monkeypatch.setattr(tasks.subprocess, "run", boom, raising=True)
    out = tasks.list_scheduled_tasks()
    assert isinstance(out, list) and out and "error" in out[0]


def test_tasks_fallback_decode_branch(monkeypatch):
    # stdout empty triggers fallback branch; still returns empty list
    def fake_run(*a, **k):
        return Proc("")
    monkeypatch.setattr(tasks.subprocess, "run", fake_run, raising=True)
    out = tasks.list_scheduled_tasks()
    assert isinstance(out, list)


def test_vt_lookup_clean_internal_client(monkeypatch):
    import httpx
    events = {"closed": False}

    class Resp:
        def __init__(self):
            self.status_code = 200
        def raise_for_status(self):
            return None
        def json(self):
            return {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 2, "undetected": 0}}}}

    class Client:
        def __init__(self, *a, **k):
            pass
        def get(self, url, headers=None):
            return Resp()
        def close(self):
            events["closed"] = True

    monkeypatch.setenv("VT_API_KEY", "k")
    monkeypatch.setattr(httpx, "Client", Client, raising=True)
    out = av.vt_lookup_hash("f"*64, client=None)
    assert out and out.get("verdict") == "clean"
    assert events["closed"] is True
