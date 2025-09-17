from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterator, List


@dataclass
class DirStat:
    path: str
    size_bytes: int
    file_count: int
    dir_count: int
    depth: int


def _iter_dir(path: str, follow_symlinks: bool) -> Iterator[os.DirEntry]:
    try:
        with os.scandir(path) as it:
            for entry in it:
                yield entry
    except (PermissionError, FileNotFoundError, OSError):
        return


def _dir_size(path: str, max_depth: int, follow_symlinks: bool, depth: int = 0) -> DirStat:
    total = 0
    files = 0
    dirs = 0

    # If max depth reached, only count files at this level
    if depth > max_depth:
        return DirStat(path, 0, 0, 0, depth)

    for entry in _iter_dir(path, follow_symlinks):
        try:
            if entry.is_symlink() and not follow_symlinks:
                continue
            if entry.is_file(follow_symlinks=follow_symlinks):
                try:
                    total += entry.stat(follow_symlinks=follow_symlinks).st_size
                except (PermissionError, FileNotFoundError, OSError):
                    pass
                files += 1
            elif entry.is_dir(follow_symlinks=follow_symlinks):
                dirs += 1
                if depth < max_depth:
                    child = _dir_size(entry.path, max_depth, follow_symlinks, depth + 1)
                    total += child.size_bytes
                    files += child.file_count
                    dirs += child.dir_count
        except (PermissionError, FileNotFoundError, OSError):
            continue

    return DirStat(path=path, size_bytes=total, file_count=files, dir_count=dirs, depth=depth)


def list_heavy_paths(
    root: str = "C:\\",
    max_depth: int = 2,
    top_n: int = 30,
    min_size_mb: int = 200,
    follow_symlinks: bool = False,
) -> List[dict]:
    """Return the heaviest directories under root (recursive, up to max_depth).

    - root: starting directory (e.g., C:\\)
    - max_depth: how deep to recurse (2-3 recommended)
    - top_n: number of top directories to return
    - min_size_mb: filter out dirs smaller than this size in MB
    - follow_symlinks: whether to follow symlinks
    """
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        raise ValueError(f"Root path is not a directory: {root}")

    results: List[DirStat] = []

    # Evaluate immediate children and recurse up to max_depth
    for entry in _iter_dir(root, follow_symlinks):
        try:
            if entry.is_dir(follow_symlinks=follow_symlinks):
                stat = _dir_size(entry.path, max_depth=max_depth, follow_symlinks=follow_symlinks, depth=1)
                results.append(stat)
        except (PermissionError, FileNotFoundError, OSError):
            continue

    # Filter and sort
    threshold = int(min_size_mb * 1024 * 1024)
    heavy = [r for r in results if r.size_bytes >= threshold]
    heavy.sort(key=lambda r: r.size_bytes, reverse=True)

    out = [
        {
            "path": r.path,
            "size_bytes": r.size_bytes,
            "size_mb": round(r.size_bytes / (1024 * 1024), 2),
            "file_count": r.file_count,
            "dir_count": r.dir_count,
            "depth": r.depth,
        }
        for r in heavy[: max(1, top_n)]
    ]
    return out
