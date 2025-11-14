from typing import Dict, List, Optional

from . import db
from . import scanner


def build_baseline(name: str, root_path: str, *, algo: str = "sha256", recursive: bool = True, limit: Optional[int] = 10000) -> Dict:
    file_infos = scanner.scan_path_parallel(root_path)
    if limit:
        file_infos = file_infos[:limit]

    baseline_id = db.insert_integrity_baseline(name=name, root_path=root_path, algo=algo)
    batch: List[Dict] = []
    for path, hash_val, size, mtime in file_infos:
        batch.append({
            "path": path,
            "hash": hash_val,
            "size": size,
            "mtime": mtime,
        })

    if batch:
        db.insert_integrity_files_batch(baseline_id=baseline_id, items=batch)
    return {"baseline_id": baseline_id, "name": name, "root_path": root_path, "algo": algo, "files_indexed": len(batch)}


def verify_baseline(name: str, *, recursive: bool = True, limit: Optional[int] = 10000, algo: Optional[str] = None) -> Dict:
    base_row = db.get_integrity_baseline_by_name(name)
    if not base_row:
        return {"error": f"Baseline '{name}' no encontrada"}
    root_path = base_row["root_path"]
    algo_eff = (algo or base_row["algo"]).lower()

    indexed = {row["path"]: row for row in db.get_integrity_files(int(base_row["id"]))}

    current_files = scanner.scan_path_parallel(root_path)
    if limit:
        current_files = current_files[:limit]


    added: List[Dict] = []
    removed: List[Dict] = []
    modified: List[Dict] = []

    seen_paths = set()

    for path, hash_val, size, mtime in current_files:
        seen_paths.add(path)
        prev = indexed.get(path)
        if not prev:
            added.append({"path": path, "hash": hash_val, "size": size, "mtime": mtime})
        else:
            if hash_val != prev["hash"] or size != int(prev.get("size") or 0):
                modified.append({
                    "path": path,
                    "old_hash": prev["hash"],
                    "new_hash": hash_val,
                    "old_size": int(prev.get("size") or 0),
                    "new_size": size,
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
