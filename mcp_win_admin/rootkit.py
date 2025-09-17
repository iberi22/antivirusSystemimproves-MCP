from typing import Dict, List, Set

import psutil


def detect_hidden_processes(limit: int = 10000) -> Dict:
    """Compara procesos vistos por WMI vs psutil y reporta discrepancias.
    No garantiza detección de rootkits; solo heurística básica.
    """
    wmi_pids: Set[int] = set()
    ps_pids: Set[int] = set(p.pid for p in psutil.process_iter(attrs=[]))
    try:
        import wmi  # type: ignore
        c = wmi.WMI()
        for proc in c.Win32_Process():
            try:
                wmi_pids.add(int(proc.ProcessId))
                if len(wmi_pids) >= limit:
                    break
            except Exception:
                continue
    except Exception as e:
        return {"error": f"WMI no disponible: {e}"}

    missing_in_psutil = sorted(list(wmi_pids - ps_pids))
    missing_in_wmi = sorted(list(ps_pids - wmi_pids))

    return {
        "summary": {
            "only_wmi": len(missing_in_psutil),
            "only_psutil": len(missing_in_wmi),
        },
        "only_wmi": missing_in_psutil,
        "only_psutil": missing_in_wmi,
    }


def check_port_owners(limit: int = 1000) -> List[Dict]:
    items: List[Dict] = []
    conns = psutil.net_connections(kind="inet")
    for c in conns[:limit]:
        try:
            if c.raddr and c.pid is None:
                items.append({
                    "laddr": f"{getattr(c.laddr, 'ip', '')}:{getattr(c.laddr, 'port', '')}",
                    "raddr": f"{getattr(c.raddr, 'ip', '')}:{getattr(c.raddr, 'port', '')}",
                    "status": c.status,
                    "pid": None,
                })
        except Exception:
            continue
    return items
