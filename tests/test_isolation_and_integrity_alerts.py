import importlib


def test_process_isolate_dryrun_actions():
    defense = importlib.import_module("mcp_win_admin.defense")
    out = defense.process_isolate_dryrun(1234)
    assert out.get("pid") == 1234
    actions = out.get("actions") or []
    kinds = [a.get("kind") for a in actions]
    assert "firewall_block_in" in kinds and "firewall_block_out" in kinds and "lower_priority" in kinds


def test_process_isolate_execute_success(monkeypatch):
    defense = importlib.import_module("mcp_win_admin.defense")
    psutil = importlib.import_module("psutil")
    subprocess = importlib.import_module("subprocess")

    class FakeProc:
        def __init__(self, pid):
            self._pid = pid
            self._aff = [0, 1, 2, 3]
        def exe(self):
            return "C:/Temp/app.exe"
        def nice(self, *a, **k):
            return None
        def cpu_affinity(self, *args):
            if args:
                self._aff = list(args[0])
                return None
            return list(self._aff)

    class FakeCP:
        def __init__(self):
            self.returncode = 0
            self.stdout = "ok"
            self.stderr = ""

    monkeypatch.setattr(psutil, "Process", lambda pid: FakeProc(pid), raising=True)
    monkeypatch.setattr(defense, "_is_system_process", lambda p: False, raising=True)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeCP(), raising=True)

    out = defense.process_isolate_execute(4321, confirm=True, policy_name="Balanced")
    assert out.get("ok") is True
    results = out.get("results") or {}
    assert results.get("firewall_in", {}).get("rc") == 0
    assert results.get("firewall_out", {}).get("rc") == 0
    assert results.get("priority_affinity", {}).get("ok") is True


def test_process_unsandbox_execute_success(monkeypatch):
    defense = importlib.import_module("mcp_win_admin.defense")
    psutil = importlib.import_module("psutil")
    subprocess = importlib.import_module("subprocess")

    class FakeProc:
        def __init__(self, pid):
            self._pid = pid
        def exe(self):
            return "C:/Temp/app.exe"

    class FakeCP:
        def __init__(self):
            self.returncode = 0
            self.stdout = "deleted"
            self.stderr = ""

    monkeypatch.setattr(psutil, "Process", lambda pid: FakeProc(pid), raising=True)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeCP(), raising=True)

    out = defense.process_unsandbox_execute(4321, confirm=True)
    assert out.get("ok") is True
    assert out.get("results", {}).get("delete_in", {}).get("rc") == 0
    assert out.get("results", {}).get("delete_out", {}).get("rc") == 0


def test_server_integrity_verify_triggers_alert(monkeypatch):
    server = importlib.import_module("mcp_win_admin.server")

    called = {"n": 0, "payload": None}

    def fake_verify_baseline(**kwargs):
        return {
            "baseline": {"name": kwargs.get("name")},
            "summary": {"added": 1, "removed": 0, "modified": 0},
        }

    def fake_notify_webhook_if_configured(event, level, data):
        called["n"] += 1
        called["payload"] = {"event": event, "level": level, "data": data}

    monkeypatch.setattr(server.intmod, "verify_baseline", lambda **k: fake_verify_baseline(**k), raising=True)
    monkeypatch.setattr(server.alertmod, "notify_webhook_if_configured", fake_notify_webhook_if_configured, raising=True)

    res = server.integrity_verify_baseline(name="baseA")
    assert res.get("summary", {}).get("added") == 1
    assert called["n"] == 1
    assert called["payload"]["event"] == "integrity_change_detected"
