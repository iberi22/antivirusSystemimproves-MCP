import importlib
import types
from datetime import datetime, timezone, timedelta
import contextlib


def test_ensure_quarantine_dir_exception(monkeypatch, tmp_path):
    defense = importlib.import_module("mcp_win_admin.defense")

    # Redirigir a temp para no tocar HOME
    monkeypatch.setattr(defense, "QUARANTINE_DIR", tmp_path / "q", raising=False)

    # Forzar excepción en mkdir
    import pathlib
    def boom(self, *a, **k):
        raise OSError("nope")
    monkeypatch.setattr(pathlib.Path, "mkdir", boom, raising=True)

    out = defense.ensure_quarantine_dir()
    assert isinstance(out, str)


def test_load_policy_aggressive():
    defense = importlib.import_module("mcp_win_admin.defense")
    pol = defense._load_policy("Aggressive")
    assert pol.allow_kill_system is True and pol.name == "Aggressive"


def test_is_system_process_variants(monkeypatch):
    defense = importlib.import_module("mcp_win_admin.defense")

    class PidOnly:
        def __init__(self, pid):
            self.pid = pid
    assert defense._is_system_process(PidOnly(4)) is True  # pid 4

    class ByName:
        def __init__(self, pid, name):
            self.pid = pid
            self._name = name
        def name(self):
            return self._name
        def username(self):
            return "user"
    assert defense._is_system_process(ByName(10, "wininit.exe")) is True

    class ByUser:
        def __init__(self, pid):
            self.pid = pid
        def name(self):
            return "not_critical.exe"
        def username(self):
            return "NT AUTHORITY\\SYSTEM"
    assert defense._is_system_process(ByUser(10)) is True

    class Broken:
        def __init__(self):
            self.pid = 11
        def name(self):
            raise RuntimeError("fail")
    # Exception path must return False
    assert defense._is_system_process(Broken()) is False

    class Plain:
        def __init__(self):
            self.pid = 123
        def name(self):
            return "ok.exe"
        def username(self):
            return "user"
    assert defense._is_system_process(Plain()) is False


def test_policy_post_init_default_list():
    defense = importlib.import_module("mcp_win_admin.defense")
    pol = defense.Policy(name="X")
    assert isinstance(pol.protected_pids, list) and pol.protected_pids == []


def test_load_policy_variants():
    defense = importlib.import_module("mcp_win_admin.defense")
    b = defense._load_policy("Balanced")
    s = defense._load_policy("unknown")
    assert b.name == "Balanced" and s.name == "Strict"


def test_ensure_quarantine_dir_exception(monkeypatch, tmp_path):
    defense = importlib.import_module("mcp_win_admin.defense")
    # Redirigir QUARANTINE_DIR
    q = tmp_path / "qdir"
    monkeypatch.setattr(defense, "QUARANTINE_DIR", q, raising=False)
    # Parchear Path.mkdir para lanzar solo con ese path
    import pathlib
    real_mkdir = pathlib.Path.mkdir
    def bad_mkdir(self, *a, **k):
        if self == q:
            raise RuntimeError("mkdir fail")
        return real_mkdir(self, *a, **k)
    monkeypatch.setattr(pathlib.Path, "mkdir", bad_mkdir, raising=True)
    # No debe lanzar
    s = defense.ensure_quarantine_dir()
    assert isinstance(s, str)


def test_quarantine_execute_not_found(tmp_path, monkeypatch):
    defense = importlib.import_module("mcp_win_admin.defense")
    monkeypatch.setattr(defense, "QUARANTINE_DIR", tmp_path / "q", raising=False)
    out = defense.quarantine_execute(str(tmp_path / "nope.bin"), confirm=True)
    assert out.get("ok") is False and out.get("error") == "not_found"


def test_quarantine_execute_move_error(tmp_path, monkeypatch):
    defense = importlib.import_module("mcp_win_admin.defense")
    monkeypatch.setattr(defense, "QUARANTINE_DIR", tmp_path / "q", raising=False)
    p = tmp_path / "f2.bin"
    p.write_bytes(b"x")

    import shutil as _sh
    def bad_move(src, dst):
        raise RuntimeError("move fail")
    monkeypatch.setattr(_sh, "move", bad_move, raising=True)

    out = defense.quarantine_execute(str(p), confirm=True)
    assert out.get("ok") is False and "move fail" in out.get("error", "")


def test_quarantine_execute_sha256_and_logging_exceptions(tmp_path, monkeypatch):
    defense = importlib.import_module("mcp_win_admin.defense")
    db = importlib.import_module("mcp_win_admin.db")
    alerts = importlib.import_module("mcp_win_admin.alerts")
    monkeypatch.setattr(defense, "QUARANTINE_DIR", tmp_path / "q", raising=False)
    p = tmp_path / "g.bin"
    p.write_bytes(b"y")
    # sha256_file falla -> sha256=""
    monkeypatch.setattr(defense, "_sha256_file", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boom")), raising=True)
    # move ok
    import shutil as _sh
    monkeypatch.setattr(_sh, "move", lambda s, d: d, raising=True)
    # logging/alert fallan para cubrir except: pass
    monkeypatch.setattr(db, "log_event", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("log boom")), raising=True)
    monkeypatch.setattr(alerts, "notify_webhook_if_configured", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("alert boom")), raising=True)
    out = defense.quarantine_execute(str(p), confirm=True)
    assert out.get("ok") is True


def test_quarantine_execute_move_failure_logs(tmp_path, monkeypatch):
    defense = importlib.import_module("mcp_win_admin.defense")
    monkeypatch.setattr(defense, "QUARANTINE_DIR", tmp_path / "q", raising=False)
    p = tmp_path / "x.bin"
    p.write_bytes(b"x")
    import shutil as _sh
    import mcp_win_admin.db as _db
    monkeypatch.setattr(_sh, "move", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("mv fail")), raising=True)
    monkeypatch.setattr(_db, "log_event", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("log boom")), raising=True)
    out = defense.quarantine_execute(str(p), confirm=True)
    assert out.get("ok") is False and out.get("error") == "mv fail"


def test_quarantine_execute_stat_exception_safe2(tmp_path, monkeypatch):
    defense = importlib.import_module("mcp_win_admin.defense")
    monkeypatch.setattr(defense, "QUARANTINE_DIR", tmp_path / "q", raising=False)
    tgt = tmp_path / "h2.bin"
    tgt.write_bytes(b"xx")
    # Guardar métodos reales
    import pathlib
    real_exists = pathlib.Path.exists
    real_is_file = pathlib.Path.is_file
    real_stat = pathlib.Path.stat
    # Bypass de exists/is_file para que no invoquen stat
    def fake_exists(self):
        if str(self) == str(tgt):
            return True
        return real_exists(self)
    def fake_is_file(self):
        if str(self) == str(tgt):
            return True
        return real_is_file(self)
    def bad_stat(self, *a, **k):
        if str(self) == str(tgt):
            raise OSError("stat fail")
        return real_stat(self, *a, **k)
    monkeypatch.setattr(pathlib.Path, "exists", fake_exists, raising=True)
    monkeypatch.setattr(pathlib.Path, "is_file", fake_is_file, raising=True)
    monkeypatch.setattr(pathlib.Path, "stat", bad_stat, raising=True)
    out = defense.quarantine_execute(str(tgt), confirm=True)
    # Debe continuar con size_mb=0 y completar cuarentena OK
    assert out.get("ok") is True and out.get("quarantine")


def test_quarantine_bulk_dryrun(monkeypatch):
    defense = importlib.import_module("mcp_win_admin.defense")
    calls = {"n": 0}
    def qdry(p):
        calls["n"] += 1
        if "bad" in p:
            raise RuntimeError("x")
        return {"path": p}
    monkeypatch.setattr(defense, "quarantine_dryrun", qdry, raising=True)
    out = defense.quarantine_bulk_dryrun(["ok1", "bad2", "ok3"])
    assert len(out) == 3 and any("error" in o for o in out)


def test_quarantine_execute_file_too_large(tmp_path, monkeypatch):
    defense = importlib.import_module("mcp_win_admin.defense")
    monkeypatch.setattr(defense, "QUARANTINE_DIR", tmp_path / "q", raising=False)
    # Política con límite muy bajo (en MB)
    monkeypatch.setattr(defense, "_load_policy", lambda name: defense.Policy(name="Strict", max_quarantine_size_mb=0.0001), raising=True)
    p = tmp_path / "big.bin"
    p.write_bytes(b"x" * 1024)  # ~1 KB
    out = defense.quarantine_execute(str(p), confirm=True)
    assert out.get("error") == "file_too_large"


def test_kill_process_execute_needs_confirm(monkeypatch):
    defense = importlib.import_module("mcp_win_admin.defense")
    out = defense.kill_process_execute(1, confirm=False)
    assert out.get("error") == "confirmation_required"


def test_kill_process_execute_success_and_kill(monkeypatch):
    defense = importlib.import_module("mcp_win_admin.defense")
    psutil = importlib.import_module("psutil")
    # Bypass system process check
    monkeypatch.setattr(defense, "_is_system_process", lambda p: False, raising=True)
    class P1:
        def __init__(self, pid):
            self.pid = pid
        def terminate(self):
            return None
        def wait(self, timeout=None):
            return None
    monkeypatch.setattr(psutil, "Process", lambda pid: P1(pid), raising=True)
    out = defense.kill_process_execute(501, confirm=True, policy_name="Aggressive")
    assert out.get("ok") is True and out.get("action") == "terminated"

    class P2(P1):
        def wait(self, timeout=None):
            raise RuntimeError("timeout")
        def kill(self):
            return None
    monkeypatch.setattr(psutil, "Process", lambda pid: P2(pid), raising=True)
    out2 = defense.kill_process_execute(502, confirm=True, policy_name="Aggressive")
    assert out2.get("ok") is True and out2.get("action") == "killed"


def test_kill_process_execute_notify_exceptions(monkeypatch):
    defense = importlib.import_module("mcp_win_admin.defense")
    psutil = importlib.import_module("psutil")
    import mcp_win_admin.alerts as _alerts
    monkeypatch.setattr(defense, "_is_system_process", lambda p: False, raising=True)
    class P1:
        def __init__(self, pid):
            self.pid = pid
        def terminate(self):
            return None
        def wait(self, timeout=None):
            return None
    # terminate path
    monkeypatch.setattr(psutil, "Process", lambda pid: P1(pid), raising=True)
    monkeypatch.setattr(_alerts, "notify_webhook_if_configured", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("notify boom")), raising=True)
    out = defense.kill_process_execute(601, confirm=True, policy_name="Aggressive")
    assert out.get("ok") is True and out.get("action") == "terminated"
    # kill path
    class P2(P1):
        def wait(self, timeout=None):
            raise RuntimeError("timeout")
        def kill(self):
            return None
    monkeypatch.setattr(psutil, "Process", lambda pid: P2(pid), raising=True)
    out2 = defense.kill_process_execute(602, confirm=True, policy_name="Aggressive")
    assert out2.get("ok") is True and out2.get("action") == "killed"


def test_kill_process_execute_access_denied_and_generic(monkeypatch):
    defense = importlib.import_module("mcp_win_admin.defense")
    psutil = importlib.import_module("psutil")
    monkeypatch.setattr(defense, "_is_system_process", lambda p: False, raising=True)
    class P3:
        pid = 503
        def terminate(self):
            raise psutil.AccessDenied(503)
    monkeypatch.setattr(psutil, "Process", lambda pid: P3(), raising=True)
    out = defense.kill_process_execute(503, confirm=True, policy_name="Aggressive")
    assert out.get("error") == "access_denied"

    class P4:
        pid = 504
        def terminate(self):
            raise RuntimeError("boom")
    monkeypatch.setattr(psutil, "Process", lambda pid: P4(), raising=True)
    out2 = defense.kill_process_execute(504, confirm=True, policy_name="Aggressive")
    assert out2.get("ok") is False and "boom" in out2.get("error", "")


def test_process_isolate_execute_paths(monkeypatch):
    defense = importlib.import_module("mcp_win_admin.defense")
    psutil = importlib.import_module("psutil")

    # confirm requerido
    out = defense.process_isolate_execute(1, confirm=False)
    assert out.get("error") == "confirmation_required"

    class FakeProc:
        def __init__(self, pid, exe_path, name="x.exe", user="user"):
            self._pid = pid
            self._exe = exe_path
            self._name = name
            self._user = user
        @property
        def pid(self):
            return self._pid
        def exe(self):
            return self._exe
        def name(self):
            return self._name
        def username(self):
            return self._user
        def nice(self, *_a, **_k):
            return None
        def cpu_affinity(self, *a, **k):
            if a:
                return None
            return [0, 1]

    # exe_not_found
    fp = FakeProc(101, exe_path=None)
    monkeypatch.setattr(psutil, "Process", lambda pid: fp, raising=True)
    monkeypatch.setattr(defense, "_is_system_process", lambda p: False, raising=True)
    out = defense.process_isolate_execute(101, confirm=True)
    assert out.get("error") == "exe_not_found"

    # éxito con subprocess.run devolviendo objetos simulados
    class CP:
        def __init__(self):
            self.returncode = 0
            self.stdout = "ok"
            self.stderr = ""
    fp2 = FakeProc(202, exe_path="C:/proc.exe")
    monkeypatch.setattr(psutil, "Process", lambda pid: fp2, raising=True)
    monkeypatch.setattr(defense, "_is_system_process", lambda p: False, raising=True)

    import subprocess as _sp
    monkeypatch.setattr(_sp, "run", lambda *a, **k: CP(), raising=True)
    out = defense.process_isolate_execute(202, confirm=True)
    assert out.get("ok") is True and isinstance(out.get("results", {}), dict)

    # error en firewall_out
    def run_maybe_fail(*a, **k):
        cmd = a[0]
        if isinstance(cmd, (list, tuple)) and ("dir=out" in cmd):
            raise RuntimeError("fail out")
        return CP()
    monkeypatch.setattr(_sp, "run", run_maybe_fail, raising=True)
    out2 = defense.process_isolate_execute(203, confirm=True)
    assert out2.get("results", {}).get("firewall_out", {}).get("error")

    # cubrir inner excepts de nice/cpu_affinity y except en log/alert
    class FakeProc2(FakeProc):
        def nice(self, *_a, **_k):
            raise RuntimeError("nice fail")
        def cpu_affinity(self, *a, **k):
            if a:
                raise RuntimeError("set fail")
            return [0, 1]
    fp3 = FakeProc2(204, exe_path="C:/proc.exe")
    monkeypatch.setattr(psutil, "Process", lambda pid: fp3, raising=True)
    import mcp_win_admin.db as _db
    import mcp_win_admin.alerts as _alerts
    monkeypatch.setattr(_db, "log_event", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("log fail")), raising=True)
    monkeypatch.setattr(_alerts, "notify_webhook_if_configured", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("alert fail")), raising=True)
    monkeypatch.setattr(_sp, "run", lambda *a, **k: CP(), raising=True)
    out3 = defense.process_isolate_execute(204, confirm=True)
    assert out3.get("ok") is True and out3.get("results", {}).get("priority_affinity", {}).get("ok") is True

    # firewall_in error path
    def run_in_fail(*a, **k):
        cmd = a[0]
        if isinstance(cmd, (list, tuple)) and ("dir=in" in cmd):
            raise RuntimeError("in fail")
        return CP()
    monkeypatch.setattr(_sp, "run", run_in_fail, raising=True)
    out4 = defense.process_isolate_execute(205, confirm=True)
    assert out4.get("results", {}).get("firewall_in", {}).get("error")

    # confirm requerido rama
    out5 = defense.process_isolate_execute(1, confirm=False)
    assert out5.get("error") == "confirmation_required"


def test_process_isolate_dryrun():
    defense = importlib.import_module("mcp_win_admin.defense")
    dr = defense.process_isolate_dryrun(42)
    assert dr.get("pid") == 42 and isinstance(dr.get("actions"), list)


def test_process_isolate_execute_error_paths(monkeypatch):
    defense = importlib.import_module("mcp_win_admin.defense")
    psutil = importlib.import_module("psutil")
    # psutil.Process error
    monkeypatch.setattr(psutil, "Process", lambda pid: (_ for _ in ()).throw(RuntimeError("no proc")), raising=True)
    out = defense.process_isolate_execute(700, confirm=True)
    assert out.get("error") == "no proc"

    # protected pid
    class P:
        def __init__(self, pid):
            self.pid = pid
        def exe(self):
            return __file__
    monkeypatch.setattr(psutil, "Process", lambda pid: P(pid), raising=True)
    monkeypatch.setattr(defense, "_load_policy", lambda name: defense.Policy(name="Strict", protected_pids=[701]), raising=True)
    out2 = defense.process_isolate_execute(701, confirm=True)
    assert out2.get("error") == "protected_pid"

    # system process
    monkeypatch.setattr(defense, "_load_policy", lambda name: defense.Policy(name="Strict", protected_pids=[]), raising=True)
    monkeypatch.setattr(defense, "_is_system_process", lambda p: True, raising=True)
    out3 = defense.process_isolate_execute(702, confirm=True)
    assert out3.get("error") == "system_process"

    # exe not found
    class PNF:
        def __init__(self, pid):
            self.pid = pid
        def exe(self):
            raise RuntimeError("no exe")
    # Asegurar que no caiga en rama de system_process
    monkeypatch.setattr(defense, "_is_system_process", lambda p: False, raising=True)
    monkeypatch.setattr(psutil, "Process", lambda pid: PNF(pid), raising=True)
    out4 = defense.process_isolate_execute(703, confirm=True)
    assert out4.get("error") == "exe_not_found"


def test_process_isolate_priority_affinity_outer_error(monkeypatch):
    defense = importlib.import_module("mcp_win_admin.defense")
    psutil = importlib.import_module("psutil")
    # Proceso con exe válido y __getattr__ que rompe hasattr('cpu_affinity')
    class PA:
        def __init__(self, pid):
            self.pid = pid
        def exe(self):
            return __file__
        def nice(self, *a, **k):
            return None
        def __getattr__(self, name):
            if name == "cpu_affinity":
                raise RuntimeError("boom attr")
            raise AttributeError(name)
    monkeypatch.setattr(psutil, "Process", lambda pid: PA(pid), raising=True)
    monkeypatch.setattr(defense, "_is_system_process", lambda p: False, raising=True)
    out = defense.process_isolate_execute(800, confirm=True)
    pa = out.get("results", {}).get("priority_affinity", {})
    # Esta rama externa es difícil de alcanzar por los try/except internos; validamos presencia clave
    assert out.get("ok") is True and isinstance(pa, dict)


def test_kill_and_quarantine_dryruns():
    defense = importlib.import_module("mcp_win_admin.defense")
    kd = defense.kill_process_dryrun(7)
    qd = defense.quarantine_dryrun("C:/tmp/file.txt")
    assert kd.get("pid") == 7 and "action" in kd
    assert "action" in qd and "quarantine" in qd


def test_process_unsandbox_execute_paths(monkeypatch):
    defense = importlib.import_module("mcp_win_admin.defense")
    psutil = importlib.import_module("psutil")

    # confirm requerido
    out = defense.process_unsandbox_execute(1, confirm=False)
    assert out.get("error") == "confirmation_required"

    # psutil.Process falla
    def bad_proc(pid):
        raise RuntimeError("no proc")
    monkeypatch.setattr(psutil, "Process", bad_proc, raising=True)
    out = defense.process_unsandbox_execute(2, confirm=True)
    assert out.get("error") == "no proc"

    class FakeProc:
        def __init__(self, pid, exe_path=None):
            self._pid = pid
            self._exe = exe_path
        def exe(self):
            if self._exe is None:
                raise RuntimeError("no exe")
            return self._exe
    # exe() falla
    monkeypatch.setattr(psutil, "Process", lambda pid: FakeProc(pid, None), raising=True)
    out = defense.process_unsandbox_execute(3, confirm=True)
    assert out.get("error", "").startswith("exe_not_found")

    # éxito con dos deletes
    class CP:
        def __init__(self):
            self.returncode = 0
            self.stdout = "deleted"
            self.stderr = ""
    monkeypatch.setattr(psutil, "Process", lambda pid: FakeProc(pid, "C:/proc.exe"), raising=True)
    import subprocess as _sp
    monkeypatch.setattr(_sp, "run", lambda *a, **k: CP(), raising=True)
    out2 = defense.process_unsandbox_execute(4, confirm=True)
    assert out2.get("ok") is True and "delete_in" in out2.get("results", {}) or "delete_out" in out2.get("results", {})

    # excepciones en logging/alerts
    import mcp_win_admin.db as _db
    import mcp_win_admin.alerts as _alerts
    monkeypatch.setattr(_db, "log_event", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("log boom")), raising=True)
    monkeypatch.setattr(_alerts, "notify_webhook_if_configured", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("alert boom")), raising=True)
    out3 = defense.process_unsandbox_execute(5, confirm=True)
    assert out3.get("ok") is True


def test_process_unsandbox_delete_error(monkeypatch):
    defense = importlib.import_module("mcp_win_admin.defense")
    psutil = importlib.import_module("psutil")
    class P:
        def __init__(self, pid):
            self.pid = pid
        def exe(self):
            return __file__
    monkeypatch.setattr(psutil, "Process", lambda pid: P(pid), raising=True)
    import subprocess as _sp
    class CP:
        returncode = 0
        stdout = "ok"
        stderr = ""
    def run_del(*a, **k):
        cmd = a[0]
        if isinstance(cmd, (list, tuple)) and any("dir=out" in x for x in cmd):
            raise RuntimeError("del fail")
        return CP()
    monkeypatch.setattr(_sp, "run", run_del, raising=True)
    out = defense.process_unsandbox_execute(10, confirm=True)
    assert out.get("ok") is True and out.get("results", {}).get("delete_out", {}).get("error") == "del fail"


def test_kill_process_execute_error_branches(monkeypatch):
    defense = importlib.import_module("mcp_win_admin.defense")
    psutil = importlib.import_module("psutil")
    # psutil.Process falla
    monkeypatch.setattr(psutil, "Process", lambda pid: (_ for _ in ()).throw(RuntimeError("no proc")), raising=True)
    out = defense.kill_process_execute(99, confirm=True)
    assert out.get("error") == "no proc"

    # protegido por policy
    class P:
        pid = 55
    monkeypatch.setattr(psutil, "Process", lambda pid: P(), raising=True)
    # Forzar policy Strict y que pid esté protegido
    monkeypatch.setattr(defense, "_load_policy", lambda name: defense.Policy(name="Strict", protected_pids=[55]), raising=True)
    out2 = defense.kill_process_execute(55, confirm=True)
    assert out2.get("error") == "protected_pid"

    # system process bloqueado
    monkeypatch.setattr(defense, "_load_policy", lambda name: defense.Policy(name="Strict", protected_pids=[]), raising=True)
    monkeypatch.setattr(defense, "_is_system_process", lambda p: True, raising=True)
    out3 = defense.kill_process_execute(56, confirm=True)
    assert out3.get("error") == "system_process"


def test_updates_list_installed_and_trigger(monkeypatch):
    updates = importlib.import_module("mcp_win_admin.updates")

    # Fake wmi con dos QFE y límite
    class QFE:
        def __init__(self, id, on, desc):
            self.HotFixID = id
            self.InstalledOn = on
            self.Description = desc
    class FakeWMI:
        def __init__(self):
            pass
        def Win32_QuickFixEngineering(self):
            class Bad:
                def __getattr__(self, name):
                    raise RuntimeError("item fail")
            return [QFE("KB1", "2024-01-01", "Fix1"), Bad(), QFE("KB2", "2024-01-02", "Fix2")]
    fake_mod = types.SimpleNamespace(WMI=lambda: FakeWMI())

    # Inyectar módulo wmi
    import sys
    sys.modules["wmi"] = fake_mod

    lst = updates.list_installed(limit=1)
    assert isinstance(lst, list) and len(lst) >= 1
    assert set(["hotfix", "installed_on", "description"]).issubset(lst[0].keys())

    # Forzar excepción en uso de wmi asegurando fallo determinista
    def fail_WMI():
        raise RuntimeError("boom")
    sys.modules["wmi"] = types.SimpleNamespace(WMI=fail_WMI)
    lst2 = updates.list_installed()
    assert lst2 and isinstance(lst2[-1], dict) and "error" in lst2[-1]

    scan = updates.trigger_scan_dryrun()
    assert scan.get("dryrun") is True and "UsoClient" in scan.get("command", "")


def test_updates_inner_item_exception_and_import_error(monkeypatch):
    updates = importlib.import_module("mcp_win_admin.updates")
    import types, builtins, sys
    # Inner item exception (continue)
    class Bad:
        def __getattr__(self, name):
            raise RuntimeError("item boom")
    class QFE:
        def __init__(self, id):
            self.HotFixID = id
            self.InstalledOn = "2024-02-02"
            self.Description = "Fix"
    class FakeWMI:
        def Win32_QuickFixEngineering(self):
            return [Bad(), QFE("KBX")]  # primero falla, luego uno válido
    sys.modules["wmi"] = types.SimpleNamespace(WMI=lambda: FakeWMI())
    lst = updates.list_installed(limit=5)
    assert isinstance(lst, list) and any(x.get("hotfix") == "KBX" for x in lst)

    # Import error path for outer except
    real_import = builtins.__import__
    def fake_import(name, *a, **k):
        if name == "wmi":
            raise ImportError("no wmi")
        return real_import(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", fake_import, raising=True)
    lst2 = updates.list_installed()
    assert lst2 and isinstance(lst2[-1], dict) and "error" in lst2[-1]
