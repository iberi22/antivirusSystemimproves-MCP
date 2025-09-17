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
