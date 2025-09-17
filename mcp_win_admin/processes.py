from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, List, Literal
import heapq

import psutil

SortKey = Literal["memory", "cpu", "pid"]


@dataclass
class ProcInfo:
    pid: int
    name: str
    username: str | None
    create_time: float | None
    cpu_percent: float | None
    memory_rss: int | None

    def to_dict(self) -> Dict:
        return asdict(self)


def _safe_proc_info(p: psutil.Process, *, need_cpu: bool, include_username: bool) -> ProcInfo:
    try:
        info = getattr(p, "info", None) or {}
        # Prefer info dict (fewer syscalls) when available
        pid = info.get("pid", p.pid)
        name = info.get("name") or (p.name() if p.is_running() else "<terminated>")
        create_time = info.get("create_time") if p.is_running() else None
        mi = info.get("memory_info")
        memory_rss = getattr(mi, "rss", None)

        # Minimize expensive calls unless explicitly requested
        cpu = p.cpu_percent(interval=0.0) if need_cpu and p.is_running() else None
        username = p.username() if include_username and p.is_running() else None

        return ProcInfo(
            pid=pid,
            name=name,
            username=username,
            create_time=create_time,
            cpu_percent=cpu,
            memory_rss=memory_rss,
        )
    except Exception:
        return ProcInfo(
            pid=getattr(p, "pid", -1) or -1,
            name="<access-denied>",
            username=None,
            create_time=None,
            cpu_percent=None,
            memory_rss=None,
        )


def list_processes(
    limit: int = 20,
    sort_by: SortKey = "memory",
    fast: bool = True,
    include_cpu: bool = False,
) -> List[Dict]:
    """Lista procesos con métricas básicas.

    - sort_by: "memory" | "cpu" | "pid"
    - limit: número máximo de elementos a devolver
    - fast: si True, evita cálculos costosos (username y CPU) salvo que se pidan
    - include_cpu: si True, calcula `cpu_percent` (rápido pero puede añadir latencia)
    """
    # Use minimal attrs to reduce per-process syscalls
    need_memory = sort_by == "memory"
    attrs = ["pid", "name"] + (["memory_info"] if need_memory else [])
    need_cpu = include_cpu or (sort_by == "cpu")
    include_username = not fast

    procs: List[ProcInfo] = []
    for p in psutil.process_iter(attrs=attrs, ad_value=None):
        procs.append(_safe_proc_info(p, need_cpu=need_cpu, include_username=include_username))

    # Choose key function
    if sort_by == "cpu":
        keyfunc = lambda x: (x.cpu_percent or -1.0)
        reverse = True
    elif sort_by == "pid":
        keyfunc = lambda x: x.pid
        reverse = False
    else:  # memory
        keyfunc = lambda x: (x.memory_rss or -1)
        reverse = True

    limit = max(1, int(limit))
    # For memory/cpu choose nlargest to avoid full sort if many processes
    if sort_by in {"memory", "cpu"} and len(procs) > limit * 2:
        top = heapq.nlargest(limit, procs, key=keyfunc)
        result = top
    else:
        procs.sort(key=keyfunc, reverse=reverse)
        result = procs[:limit]

    return [p.to_dict() for p in result]
