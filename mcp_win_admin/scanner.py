from mcp_win_admin.native_scanner import scan_path_parallel as _scan_path_parallel
from typing import List, Tuple

def scan_path_parallel(path: str) -> List[Tuple[str, str, int, float]]:
    """
    Scans a path in parallel using the native Rust module.

    Args:
        path: The path to scan.

    Returns:
        A list of tuples, where each tuple contains the file path, its SHA256 hash,
        size, and modification time.
    """
    return _scan_path_parallel(path)
