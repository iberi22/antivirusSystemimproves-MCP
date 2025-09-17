from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Dict, List

import psutil


@dataclass
class PerformanceSnapshot:
    ts_iso: str
    cpu_percent: float
    mem_percent: float
    mem_total: int
    mem_used: int
    disk_percent: float
    uptime_seconds: int
    processes_total: int

    def to_dict(self) -> Dict[str, float]:
        return asdict(self)


def _overall_disk_percent() -> float:
    """Calcula el porcentaje global de uso de disco considerando particiones locales."""
    total = 0
    used = 0
    for p in psutil.disk_partitions(all=False):
        # Filtrar CDs/USBs o sin montaje
        if p.fstype and os.name == "nt":
            # En Windows, incluir solo unidades fijas
            try:
                usage = psutil.disk_usage(p.mountpoint)
            except Exception:
                continue
            total += usage.total
            used += usage.used
    return (used / total * 100.0) if total else 0.0


def get_performance_snapshot() -> PerformanceSnapshot:
    """Obtiene un snapshot rápido de rendimiento (no bloqueante)."""
    cpu = psutil.cpu_percent(interval=0.2)
    vm = psutil.virtual_memory()
    disk = _overall_disk_percent()

    boot_ts = psutil.boot_time()
    now_ts = datetime.now().timestamp()
    uptime = int(now_ts - boot_ts)

    try:
        proc_total = len(psutil.pids())
    except Exception:
        proc_total = 0

    snap = PerformanceSnapshot(
        ts_iso=datetime.now(timezone.utc).isoformat(),
        cpu_percent=float(cpu),
        mem_percent=float(vm.percent),
        mem_total=int(vm.total),
        mem_used=int(vm.used),
        disk_percent=float(disk),
        uptime_seconds=uptime,
        processes_total=proc_total,
    )
    return snap
