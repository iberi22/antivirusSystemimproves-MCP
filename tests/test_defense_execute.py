import importlib
import json


def test_quarantine_execute_small_file_strict_confirm(tmp_path, monkeypatch):
    defense = importlib.import_module("mcp_win_admin.defense")

    # Redirigir cuarentena a temp
    qdir = tmp_path / "quarantine"
    monkeypatch.setattr(defense, "QUARANTINE_DIR", qdir, raising=False)

    # Crear archivo pequeño
    p = tmp_path / "mal.bin"
    p.write_bytes(b"malware")

    out = defense.quarantine_execute(str(p), confirm=True, policy_name="Strict")
    assert out.get("ok") is True
    dest = out.get("quarantine")
    assert dest and (qdir in (qdir.parent / "quarantine", qdir))  # sanity

    # Verificar que está movido y manifiesto
    dest_path = qdir / (dest.split("\\")[-1].split("/")[-1]) if isinstance(dest, str) else qdir
    assert (qdir.exists())
    # Buscar manifiesto correspondiente
    manifests = list(qdir.glob("*.manifest.json"))
    assert manifests, "Manifiesto de cuarentena no creado"
    data = json.loads(manifests[0].read_text(encoding="utf-8"))
    assert data.get("action") == "quarantine_move"
    assert data.get("sha256") and len(data["sha256"]) == 64


def test_quarantine_execute_requires_confirm(tmp_path, monkeypatch):
    defense = importlib.import_module("mcp_win_admin.defense")
    monkeypatch.setattr(defense, "QUARANTINE_DIR", tmp_path / "q", raising=False)
    p = tmp_path / "x.bin"
    p.write_bytes(b"x")
    out = defense.quarantine_execute(str(p), confirm=False, policy_name="Strict")
    assert out.get("ok") is False
    assert out.get("error") == "confirmation_required"


def test_quarantine_execute_too_large_with_mock_policy(tmp_path, monkeypatch):
    defense = importlib.import_module("mcp_win_admin.defense")
    monkeypatch.setattr(defense, "QUARANTINE_DIR", tmp_path / "q", raising=False)

    # Política con límite muy pequeño (1 MB)
    class P(defense.Policy):
        pass

    monkeypatch.setattr(
        defense,
        "_load_policy",
        lambda name: P(name="Strict", allow_kill_system=False, protected_pids=[0, 4], max_quarantine_size_mb=1, require_confirm=True),
        raising=True,
    )

    # Crear archivo de ~2 MB
    big = tmp_path / "big.bin"
    big.write_bytes(b"\0" * (2 * 1024 * 1024))
    out = defense.quarantine_execute(str(big), confirm=True, policy_name="Strict")
    assert out.get("ok") is False
    assert out.get("error") == "file_too_large"


def test_kill_process_execute_blocks_system(monkeypatch):
    defense = importlib.import_module("mcp_win_admin.defense")
    psutil = importlib.import_module("psutil")

    # Simular proceso cualquiera
    class FakeProc:
        def __init__(self, pid):
            self.pid = pid

    monkeypatch.setattr(psutil, "Process", lambda pid: FakeProc(pid), raising=True)
    # Forzar que sea considerado de sistema
    monkeypatch.setattr(defense, "_is_system_process", lambda p: True, raising=True)

    out = defense.kill_process_execute(12345, confirm=True, policy_name="Strict")
    assert out.get("ok") is False
    assert out.get("error") == "system_process"


def test_kill_process_execute_kill_path(monkeypatch):
    defense = importlib.import_module("mcp_win_admin.defense")
    psutil = importlib.import_module("psutil")

    class FakeProc:
        def __init__(self, pid):
            self.pid = pid
            self.terminated = False
            self.killed = False

        def terminate(self):
            self.terminated = True

        def wait(self, timeout=3):
            # Forzar ruta de kill
            raise Exception("timeout")

        def kill(self):
            self.killed = True

    fp = FakeProc(99999)
    monkeypatch.setattr(psutil, "Process", lambda pid: fp, raising=True)
    monkeypatch.setattr(defense, "_is_system_process", lambda p: False, raising=True)

    out = defense.kill_process_execute(99999, confirm=True, policy_name="Balanced")
    assert out.get("ok") is True
    assert out.get("action") == "killed"
