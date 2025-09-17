from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List

try:
    import winreg  # type: ignore
except Exception:  # pragma: no cover
    winreg = None  # type: ignore


RUN_PATHS = [
    ("HKCU", r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
    ("HKCU", r"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
    ("HKLM", r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
    ("HKLM", r"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
]


def _enum_run_key(hive_name: str, subkey: str) -> List[Dict]:
    items: List[Dict] = []
    if winreg is None:
        return [{"error": "winreg no disponible"}]
    hive = winreg.HKEY_CURRENT_USER if hive_name == "HKCU" else winreg.HKEY_LOCAL_MACHINE
    try:
        with winreg.OpenKey(hive, subkey) as key:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    items.append({
                        "hive": hive_name,
                        "subkey": subkey,
                        "name": name,
                        "command": value,
                    })
                    i += 1
                except OSError:
                    break
    except Exception as e:
        items.append({"hive": hive_name, "subkey": subkey, "error": str(e)})
    return items


def _startup_dirs() -> List[Path]:
    paths: List[Path] = []
    # Current user
    appdata = os.getenv("APPDATA")
    if appdata:
        paths.append(Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
    # All users
    programdata = os.getenv("PROGRAMDATA")
    if programdata:
        paths.append(Path(programdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
    return [p for p in paths if p.exists()]


def list_startup(limit: int = 200) -> List[Dict]:
    """Lista elementos de inicio (autoruns) desde registro y carpetas Startup."""
    items: List[Dict] = []
    # Registry
    for hive, subkey in RUN_PATHS:
        for it in _enum_run_key(hive, subkey):
            items.append(it)
            if len(items) >= limit:
                return items
    # Startup folders
    for d in _startup_dirs():
        try:
            for child in d.iterdir():
                if child.is_file():
                    items.append({
                        "hive": "FS",
                        "subkey": str(d),
                        "name": child.name,
                        "command": str(child),
                    })
                    if len(items) >= limit:
                        return items
        except Exception:
            continue
    return items
