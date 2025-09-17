from typing import Dict, List


def list_drivers(limit: int = 500) -> List[Dict]:
    items: List[Dict] = []
    # Try WMI first
    try:
        import wmi  # type: ignore
        c = wmi.WMI()
        for d in c.Win32_SystemDriver():
            try:
                items.append({
                    "name": d.Name,
                    "display_name": getattr(d, "DisplayName", None),
                    "state": getattr(d, "State", None),
                    "status": getattr(d, "Status", None),
                    "path": getattr(d, "PathName", None),
                    "start_mode": getattr(d, "StartMode", None),
                    "type": getattr(d, "ServiceType", None),
                })
                if len(items) >= limit:
                    break
            except Exception:
                continue
        return items
    except Exception:
        pass
    # Fallback: none
    return items
