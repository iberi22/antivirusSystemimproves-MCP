from mcp_win_admin.native_scanner import scan_path_parallel as _scan_path_parallel

def scan_path_parallel(path: str) -> list[str]:
    """
    Scans a path in parallel using the native Rust module.

    Args:
        path: The path to scan.

    Returns:
        A list of SHA256 hashes of the files found.
    """
    return _scan_path_parallel(path)
