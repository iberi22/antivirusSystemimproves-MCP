import importlib


def test_defense_quarantine_dryrun(tmp_path):
    defense = importlib.import_module("mcp_win_admin.defense")
    p = tmp_path / "mal.exe"
    p.write_bytes(b"xx")
    out = defense.quarantine_dryrun(str(p))
    assert out["action"]["kind"] == "quarantine_move"
    assert "Move-Item" in out["action"]["command"]


def test_integrity_diff_baselines(tmp_path):
    # Crear dos baselines mínimos y compararlos
    db = importlib.import_module("mcp_win_admin.db")
    integrity = importlib.import_module("mcp_win_admin.integrity")

    # baseline A
    (tmp_path / "a").mkdir()
    f1 = tmp_path / "a" / "file1.bin"
    f1.write_bytes(b"one")
    integrity.build_baseline("A", str(tmp_path / "a"), recursive=True, limit=100)

    # baseline B con cambios
    (tmp_path / "b").mkdir()
    f1b = tmp_path / "b" / "file1.bin"
    f1b.write_bytes(b"two")  # modificado
    f2b = tmp_path / "b" / "file2.bin"
    f2b.write_bytes(b"new")  # añadido
    integrity.build_baseline("B", str(tmp_path / "b"), recursive=True, limit=100)

    diff = integrity.diff_baselines("A", "B")
    # Al ser rutas distintas, los archivos aparecen como added/removed, no modified
    assert diff["summary"]["added"] >= 1
    assert diff["summary"]["removed"] >= 1
