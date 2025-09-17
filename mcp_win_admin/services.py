from __future__ import annotations

from typing import Dict, List, Optional

import psutil


def list_services(status: Optional[str] = None, limit: int = 200) -> List[Dict]:
    """Lista servicios de Windows.

    - status: filtra por estado (e.g., 'running', 'stopped'). None = todos.
    - limit: máximo de resultados.
    """
    items: List[Dict] = []
    try:
        for s in psutil.win_service_iter():  # type: ignore[attr-defined]
            try:
                d = s.as_dict()
                if status and d.get("status") != status:
                    continue
                items.append(
                    {
                        "name": d.get("name"),
                        "display_name": d.get("display_name"),
                        "status": d.get("status"),
                        "start_type": d.get("start_type"),
                        "binpath": d.get("binpath"),
                    }
                )
                if len(items) >= limit:
                    break
            except Exception:
                continue
    except Exception as e:
        items.append({"error": str(e)})
    return items
