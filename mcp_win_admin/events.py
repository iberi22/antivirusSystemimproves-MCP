from __future__ import annotations

from typing import Dict, List
from datetime import datetime

try:
    import win32evtlog  # type: ignore
    import win32con  # type: ignore
except Exception:  # pragma: no cover
    win32evtlog = None  # type: ignore
    win32con = None  # type: ignore


def list_events(channel: str = "System", limit: int = 100) -> List[Dict]:
    """Lee eventos recientes del Windows Event Log.

    - channel: 'System' | 'Application' | 'Security' (puede requerir privilegios)
    - limit: número máximo de eventos
    """
    items: List[Dict] = []
    if win32evtlog is None:
        return [{"error": "pywin32 no disponible o no soportado"}]
    try:
        h = win32evtlog.OpenEventLog(None, channel)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        read = True
        while read and len(items) < limit:
            records = win32evtlog.ReadEventLog(h, flags, 0)
            if not records:
                break
            for rec in records:
                try:
                    ts = rec.TimeGenerated
                    # Convert to ISO string if possible
                    ts_iso = None
                    if hasattr(ts, "Format"):
                        ts_iso = ts.Format()  # pywin32 time object
                    else:
                        try:
                            ts_iso = datetime.fromtimestamp(int(ts)).isoformat()
                        except Exception:
                            ts_iso = str(ts)
                    items.append(
                        {
                            "EventID": rec.EventID & 0xFFFF,
                            "SourceName": rec.SourceName,
                            "Category": rec.EventCategory,
                            "EventType": rec.EventType,
                            "TimeGenerated": ts_iso,
                            "RecordNumber": rec.RecordNumber,
                        }
                    )
                    if len(items) >= limit:
                        break
                except Exception:
                    continue
        win32evtlog.CloseEventLog(h)
    except Exception as e:  # permisos o canal inexistente
        items.append({"error": str(e), "channel": channel})
    return items
