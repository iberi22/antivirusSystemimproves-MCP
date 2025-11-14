from pathlib import Path

from mcp_win_admin import av


def test_hash_and_scan_path_basic(tmp_path: Path):
    f = tmp_path / "sample.txt"
    f.write_text("hello world", encoding="utf-8")

    # Scan without cloud to avoid network in tests
    res = av.scan_path(str(f), recursive=False, limit=None, algo="sha256", use_cloud=False)
    assert isinstance(res, list) and len(res) == 1
    item = res[0]
    assert item.get("path") == str(f)
    assert item.get("algo") == "sha256"
    assert isinstance(item.get("hash"), str) and len(item["hash"]) > 0
    assert item.get("verdict") in {"unknown", "clean", "suspicious", "malicious"}


def test_check_hash_cache_only_unknown():
    # Random hash unlikely to be cached; expect unknown without cloud
    h = "0" * 64
    out = av.check_hash(h, algo="sha256", use_cloud=False)
    assert out["hash"] == h
    assert out["algo"] == "sha256"
    assert out["verdict"] in {"unknown", "clean", "suspicious", "malicious"}


def test_scan_path_modern_returns_paths(tmp_path: Path):
    """Verifica que av_scan_path_modern devuelve las rutas de archivo correctas."""
    # Crea algunos archivos de prueba
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "f1.txt").write_text("file 1")
    (tmp_path / "f2.txt").write_text("file 2")

    # Escanea el directorio
    results = av.scan_path_modern(str(tmp_path), use_cloud=False)

    # Verifica que los resultados contienen las rutas de archivo correctas
    paths = {item.get("path") for item in results}
    expected_paths = {
        str(tmp_path / "a" / "f1.txt"),
        str(tmp_path / "f2.txt"),
    }
    assert paths == expected_paths
