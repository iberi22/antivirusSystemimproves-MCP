from __future__ import annotations

import psutil
from typing import Dict, List

from mcp_win_admin import processes as proc_mod
from mcp_win_admin import connections as conn_mod


def snapshot() -> Dict:
    vm = psutil.virtual_memory()
    disks = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            disks.append({
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
                "percent": usage.percent,
            })
        except Exception:
            continue
    return {
        "cpu_percent": psutil.cpu_percent(interval=None),
        "cpu_count": psutil.cpu_count(logical=True),
        "memory": {
            "total": vm.total,
            "available": vm.available,
            "used": vm.used,
            "percent": vm.percent,
        },
        "disks": disks,
    }


def top_processes(by: str = "memory", limit: int = 10) -> List[Dict]:
    sort_by = by if by in {"memory", "cpu", "pid"} else "memory"
    include_cpu = sort_by == "cpu"
    # Para CPU necesitamos cálculos precisos: desactivar fast.
    fast = False if sort_by == "cpu" else True
    items = proc_mod.list_processes(limit=limit, sort_by=sort_by, fast=fast, include_cpu=include_cpu)
    return items


def connections(limit: int = 50) -> List[Dict]:
    return conn_mod.list_connections(limit=limit, kind="inet", listening_only=False, include_process=True)
