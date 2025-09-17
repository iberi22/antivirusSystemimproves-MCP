from typing import Dict, List, Optional

import psutil
from . import config as cfg


def list_connections(
    *,
    limit: int = 100,
    kind: str = "inet",
    listening_only: bool = False,
    include_process: bool = False,
) -> List[Dict]:
    """Lista conexiones de red.

    - kind: 'inet', 'tcp', 'udp', etc.
    - listening_only: True para solo sockets en LISTEN
    - include_process: añade nombre del proceso (puede ser costoso o denegado)
    """
    # Aplicar cap de límite según configuración
    limit = cfg.clamp_limit(limit, "connections")
    items: List[Dict] = []
    try:
        for c in psutil.net_connections(kind=kind):
            try:
                if listening_only and c.status != psutil.CONN_LISTEN:
                    continue
                item: Dict = {
                    "fd": c.fd,
                    "family": int(getattr(c.family, "value", c.family)),
                    "type": int(getattr(c.type, "value", c.type)),
                    "laddr": f"{getattr(c.laddr, 'ip', '')}:{getattr(c.laddr, 'port', '')}" if c.laddr else None,
                    "raddr": f"{getattr(c.raddr, 'ip', '')}:{getattr(c.raddr, 'port', '')}" if c.raddr else None,
                    "status": c.status,
                    "pid": c.pid,
                }
                if include_process and c.pid:
                    try:
                        p = psutil.Process(c.pid)
                        item["process_name"] = p.name()
                    except Exception:
                        item["process_name"] = None
                items.append(item)
                if len(items) >= limit:
                    break
            except Exception:
                continue
    except Exception as e:
        items.append({"error": str(e)})
    return items
