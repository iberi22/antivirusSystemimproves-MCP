from typing import Dict, List


def list_installed(limit: int = 200) -> List[Dict]:
    items: List[Dict] = []
    try:
        import wmi  # type: ignore
        c = wmi.WMI()
        for qfe in c.Win32_QuickFixEngineering():
            try:
                items.append({
                    "hotfix": getattr(qfe, "HotFixID", None),
                    "installed_on": getattr(qfe, "InstalledOn", None),
                    "description": getattr(qfe, "Description", None),
                })
                if len(items) >= limit:
                    break
            except Exception:
                continue
    except Exception as e:
        items.append({"error": str(e)})
    return items


def trigger_scan_dryrun() -> Dict:
    # Windows 10+: UsoClient.exe StartScan (requiere elevación)
    return {"dryrun": True, "command": "UsoClient.exe StartScan"}
