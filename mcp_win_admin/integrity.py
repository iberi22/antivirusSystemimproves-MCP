import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from . import db
from .av import _hash_file


@dataclass
class FileInfo:
    path: str
    hash: str
    size: int
    mtime: float


def _walk_files(base: Path, recursive: bool = True, limit: Optional[int] = None) -> Iterable[Path]:
    count = 0
    if base.is_file():
        yield base
        return
    if recursive:
        for root, _, files in os.walk(base):
            for name in files:
                p = Path(root) / name
                yield p
                count += 1
                if limit and count >= limit:
                    return
    else:
        for p in base.iterdir():
            if p.is_file():
                yield p
                count += 1
                if limit and count >= limit:
                    return


def build_baseline(name: str, root_path: str, *, algo: str = "sha256", recursive: bool = True, limit: Optional[int] = 10000) -> Dict:
    base = Path(root_path).expanduser()
    files = list(_walk_files(base, recursive=recursive, limit=limit))
    baseline_id = db.insert_integrity_baseline(name=name, root_path=str(base), algo=algo)
    batch: List[Dict] = []
    for f in files:
        try:
            st = f.stat()
            h = _hash_file(f, algo)
            batch.append({
                "path": str(f.resolve()),
                "hash": h,
                "size": int(st.st_size),
                "mtime": float(st.st_mtime),
            })
        except Exception:
            continue
    if batch:
        db.insert_integrity_files_batch(baseline_id=baseline_id, items=batch)
    return {"baseline_id": baseline_id, "name": name, "root_path": str(base), "algo": algo, "files_indexed": len(batch)}


essential_keys = ("path", "hash", "size", "mtime")


def verify_baseline(name: str, *, recursive: bool = True, limit: Optional[int] = 10000, algo: Optional[str] = None) -> Dict:
    base_row = db.get_integrity_baseline_by_name(name)
    if not base_row:
        return {"error": f"Baseline '{name}' no encontrada"}
    root_path = Path(base_row["root_path"]).expanduser()
    algo_eff = (algo or base_row["algo"]).lower()

    indexed = {row["path"]: row for row in db.get_integrity_files(int(base_row["id"]))}
    current_files = list(_walk_files(root_path, recursive=recursive, limit=limit))

    added: List[Dict] = []
    removed: List[Dict] = []
    modified: List[Dict] = []

    seen_paths = set()

    for f in current_files:
        p = str(f.resolve())
        seen_paths.add(p)
        try:
            st = f.stat()
            h = _hash_file(f, algo_eff)
        except Exception as e:
            modified.append({"path": p, "error": str(e)})
            continue
        prev = indexed.get(p)
        if not prev:
            added.append({"path": p, "hash": h, "size": int(st.st_size), "mtime": float(st.st_mtime)})
        else:
            if h != prev["hash"] or int(st.st_size) != int(prev.get("size") or 0):
                modified.append({
                    "path": p,
                    "old_hash": prev["hash"],
                    "new_hash": h,
                    "old_size": int(prev.get("size") or 0),
                    "new_size": int(st.st_size),
                })

    for p, prev in indexed.items():
        if p not in seen_paths:
            removed.append({"path": p, "hash": prev["hash"], "size": int(prev.get("size") or 0)})

    return {
        "baseline": {"id": int(base_row["id"]), "name": base_row["name"], "root_path": base_row["root_path"], "algo": algo_eff},
        "summary": {"added": len(added), "removed": len(removed), "modified": len(modified)},
        "added": added,
        "removed": removed,
        "modified": modified,
    }


def list_baselines() -> List[Dict]:
    """Lista baselines de integridad guardados (wrapper para facilitar tests/monkeypatch)."""
    return db.list_integrity_baselines()


def diff_baselines(name_a: str, name_b: str) -> Dict:
    """Compara dos baselines persistidos y devuelve diferencias agregadas.

    No accede al filesystem; utiliza los índices de archivos almacenados.
    """
    a = db.get_integrity_baseline_by_name(name_a)
    b = db.get_integrity_baseline_by_name(name_b)
    if not a or not b:
        missing = []
        if not a:
            missing.append(name_a)
        if not b:
            missing.append(name_b)
        return {"error": f"Baselines no encontrados: {', '.join(missing)}"}

    files_a = {row["path"]: row for row in db.get_integrity_files(int(a["id"]))}
    files_b = {row["path"]: row for row in db.get_integrity_files(int(b["id"]))}

    added: List[Dict] = []    # en B pero no en A
    removed: List[Dict] = []  # en A pero no en B
    modified: List[Dict] = [] # en ambos pero con hash/size distinto

    for p, ra in files_a.items():
        rb = files_b.get(p)
        if rb is None:
            removed.append({"path": p, "hash": ra["hash"], "size": int(ra.get("size") or 0)})
        else:
            if ra["hash"] != rb["hash"] or int(ra.get("size") or 0) != int(rb.get("size") or 0):
                modified.append({
                    "path": p,
                    "a_hash": ra["hash"],
                    "b_hash": rb["hash"],
                    "a_size": int(ra.get("size") or 0),
                    "b_size": int(rb.get("size") or 0),
                })

    for p, rb in files_b.items():
        if p not in files_a:
            added.append({"path": p, "hash": rb["hash"], "size": int(rb.get("size") or 0)})

    return {
        "baseline_a": {"id": int(a["id"]), "name": a["name"], "root_path": a["root_path"], "algo": a["algo"]},
        "baseline_b": {"id": int(b["id"]), "name": b["name"], "root_path": b["root_path"], "algo": b["algo"]},
        "summary": {"added": len(added), "removed": len(removed), "modified": len(modified)},
        "added": added,
        "removed": removed,
        "modified": modified,
    }
