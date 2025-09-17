import sys
import types
from pathlib import Path
import pytest


@pytest.fixture
def fake_wmi(monkeypatch):
    mod = types.ModuleType("wmi")

    class _Drv:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    class _QFE:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    class _WMI:
        def Win32_SystemDriver(self):
            return [
                _Drv(Name="drv1", DisplayName="Driver 1", State="Running", Status="OK", PathName="C:/d1.sys", StartMode="Auto", ServiceType="kernel"),
                _Drv(Name="drv2", DisplayName="Driver 2", State="Stopped", Status="ERROR", PathName="C:/d2.sys", StartMode="Manual", ServiceType="file")
            ]

        def Win32_QuickFixEngineering(self):
            return [
                _QFE(HotFixID="KB1", InstalledOn="2024-01-01", Description="Sec"),
                _QFE(HotFixID="KB2", InstalledOn="2024-02-01", Description="Bugfix"),
            ]

    mod.WMI = _WMI
    monkeypatch.setitem(sys.modules, "wmi", mod)
    return mod


def test_services_list_basic(monkeypatch):
    import types
    from mcp_win_admin import services

    class Svc:
        def __init__(self, name, status):
            self._name = name
            self._status = status
        def as_dict(self):
            return {"name": self._name, "display_name": self._name.title(), "status": self._status, "start_type": "auto", "binpath": "C:/x.exe"}

    def fake_iter():
        for s in [Svc("a", "running"), Svc("b", "stopped")]:
            yield s
    monkeypatch.setattr(services.psutil, "win_service_iter", lambda: fake_iter(), raising=True)
    all_items = services.list_services()
    assert len(all_items) >= 2
    only_running = services.list_services(status="running", limit=1)
    assert len(only_running) == 1 and only_running[0]["status"] == "running"


def test_drivers_and_updates_with_wmi(fake_wmi):
    from mcp_win_admin import drivers, updates
    d = drivers.list_drivers(limit=1)
    assert d and isinstance(d[0], dict)
    u = updates.list_installed(limit=5)
    assert any(x.get("hotfix") == "KB1" for x in u)


def test_drivers_no_wmi(monkeypatch):
    from mcp_win_admin import drivers
    monkeypatch.setitem(sys.modules, "wmi", None)
    out = drivers.list_drivers(limit=2)
    assert isinstance(out, list)


def test_firewall_list_and_export(monkeypatch, tmp_path: Path):
    from mcp_win_admin import firewall

    sample = """
Rule Name: TestRule
Enabled: Yes
Direction: Out
Action: Block

Nombre de regla: ReglaES
Habilitada: Sí
Dirección: Entrada
Acción: Permitir
""".strip()
    def fake_check_output(cmd, shell, text, stderr, timeout):
        if cmd[:3] == ["netsh", "advfirewall", "firewall"]:
            return sample
        raise RuntimeError("unexpected")
    monkeypatch.setattr(firewall.subprocess, "check_output", fake_check_output)
    items = firewall.list_rules(limit=10)
    assert any(it.get("name") == "TestRule" for it in items)

    # export_rules success
    def fake_check_output_export(cmd, shell, text, stderr, timeout):
        return "OK"
    monkeypatch.setattr(firewall.subprocess, "check_output", fake_check_output_export)
    ok = firewall.export_rules(str(tmp_path / "fw.wfw"))
    assert ok.get("ok") is True

    # error path
    def raise_err(*a, **k):
        raise RuntimeError("fail")
    monkeypatch.setattr(firewall.subprocess, "check_output", raise_err)
    err = firewall.export_rules(str(tmp_path / "bad.wfw"))
    assert "error" in err

    # dryrun
    assert firewall.block_ip_dryrun("1.2.3.4")["dryrun"] is True


def test_tasks_list(monkeypatch):
    from mcp_win_admin import tasks
    # Minimal CSV with headers and two rows
    csv = "TaskName,Next Run Time,Status,Last Run Time,Author,Task To Run\n" \
          "\\TaskA, ,Ready, ,user,cmd.exe\n" \
          "\\TaskB, ,Disabled, ,user,cmd2.exe\n"
    class CP:
        def __init__(self, out):
            self.stdout = out
    def fake_run(*a, **k):
        return CP(csv)
    monkeypatch.setattr(tasks.subprocess, "run", fake_run)
    all_items = tasks.list_scheduled_tasks()
    assert len(all_items) == 2
    ready = tasks.list_scheduled_tasks(state="Ready")
    assert len(ready) == 1 and ready[0]["Status"] == "Ready"


def test_events_list_and_error(monkeypatch):
    from mcp_win_admin import events
    # Fake pywin32 modules
    evt = types.SimpleNamespace(EVENTLOG_BACKWARDS_READ=1, EVENTLOG_SEQUENTIAL_READ=2)

    class Rec:
        def __init__(self, eid):
            self.EventID = eid
            self.SourceName = "Src"
            self.EventCategory = 0
            self.EventType = 1
            self.TimeGenerated = 0
            self.RecordNumber = eid
    def OpenEventLog(a, b):
        return object()
    def ReadEventLog(h, flags, rec):
        # two records then stop
        if not hasattr(ReadEventLog, "called"):
            ReadEventLog.called = 1
            return [Rec(100), Rec(101)]
        return []
    def CloseEventLog(h):
        return None
    evt.OpenEventLog = OpenEventLog
    evt.ReadEventLog = ReadEventLog
    evt.CloseEventLog = CloseEventLog

    # Patch directly the symbols used inside mcp_win_admin.events
    monkeypatch.setattr(events, "win32evtlog", evt, raising=False)

    out = events.list_events(limit=2)
    assert len(out) == 2
    assert isinstance(out[0].get("EventID"), int)

    # error branch
    def bad_OpenEventLog(a, b):
        raise RuntimeError("no access")
    evt.OpenEventLog = bad_OpenEventLog
    err = events.list_events(limit=1)
    assert err and "error" in err[0]


def test_usn_query(monkeypatch):
    from mcp_win_admin import monitor_usn
    monkeypatch.setattr(monitor_usn.platform, "system", lambda: "Windows")

    class CP:
        def __init__(self, rc, out, err=""):
            self.returncode = rc
            self.stdout = out
            self.stderr = err
    def ok_run(*a, **k):
        return CP(0, "Journal ID: 0x1\nFirst USN: 1\nNext USN: 2\nMaximum Size: 4096\n")
    monkeypatch.setattr(monitor_usn.subprocess, "run", ok_run)
    ok = monitor_usn.query_usn_info("C")
    assert ok.get("Journal ID") == "0x1" and ok.get("drive") == "C"

    def bad_run(*a, **k):
        return CP(1, "", "denied")
    monkeypatch.setattr(monitor_usn.subprocess, "run", bad_run)
    err = monitor_usn.query_usn_info("D")
    assert err.get("error")


def test_rootkit(monkeypatch):
    from mcp_win_admin import rootkit
    class P:
        def __init__(self, pid):
            self.pid = pid
    monkeypatch.setattr(rootkit.psutil, "process_iter", lambda attrs=None: [P(1), P(2)])

    # provide WMI with different set
    mod = types.ModuleType("wmi")
    class _WMI:
        def Win32_Process(self):
            class _Rec:
                def __init__(self, pid): self.ProcessId = pid
            return [_Rec(2), _Rec(3)]
    mod.WMI = _WMI
    monkeypatch.setitem(sys.modules, "wmi", mod)

    diff = rootkit.detect_hidden_processes()
    assert diff["summary"]["only_wmi"] >= 0

    # check_port_owners
    class Conn:
        def __init__(self, l, r, status, pid):
            self.laddr = types.SimpleNamespace(ip=l.split(":")[0], port=int(l.split(":")[1]))
            self.raddr = types.SimpleNamespace(ip=r.split(":")[0], port=int(r.split(":")[1]))
            self.status = status
            self.pid = pid
    monkeypatch.setattr(rootkit.psutil, "net_connections", lambda kind=None: [Conn("127.0.0.1:1", "8.8.8.8:53", "ESTABLISHED", None), Conn("127.0.0.1:2", "1.1.1.1:53", "ESTABLISHED", 123)])
    out = rootkit.check_port_owners()
    assert any(o.get("pid") is None for o in out)


def test_yara_scan(monkeypatch, tmp_path: Path):
    from mcp_win_admin import yara_scan

    # Without yara
    monkeypatch.setitem(sys.modules, "yara", None)
    err = yara_scan.scan_path(str(tmp_path), rule_text=None)
    assert "error" in err

    # With fake yara
    class FakeRule:
        def match(self, path):
            class M:
                def __init__(self):
                    self.rule = "R1"; self.tags = ["t"]; self.meta = {"k": "v"}
            return [M()]
    class FakeYara:
        def compile(self, source=None, filepath=None, filepaths=None):
            return FakeRule()
    fake_mod = types.SimpleNamespace()
    fake_mod.compile = FakeYara().compile
    monkeypatch.setitem(sys.modules, "yara", fake_mod)

    # create sample file
    f = tmp_path / "a.bin"
    f.write_bytes(b"xyz")
    res = yara_scan.scan_path(str(tmp_path), rule_text="rule R1 { condition: true }", recursive=True, limit=10)
    assert res.get("scanned") >= 1

    # test_rule
    t = yara_scan.test_rule("rule R1 { condition: true }", str(f))
    assert "matches" in t or "error" in t
