from __future__ import annotations

import csv
import subprocess
from io import StringIO
from typing import Dict, List


def list_scheduled_tasks(limit: int = 200, state: str = "") -> List[Dict]:
    """Lista tareas programadas usando `schtasks`.

    - state: filtra por estado si no es vacío (e.g., 'Ready', 'Running', 'Disabled')
    - limit: máximo de resultados
    """
    try:
        # CSV output for easier parsing
        proc = subprocess.run(
            ["schtasks", "/Query", "/FO", "CSV", "/V"],
            capture_output=True,
            text=True,
            check=True,
            encoding="utf-8",
        )
    except Exception as e:
        return [{"error": str(e)}]

    out = proc.stdout
    # schtasks may produce empty/garbled output; attempt a best-effort re-decode if empty
    if not out:
        try:
            out = proc.stdout.encode("utf-8", errors="ignore").decode("utf-8", errors="ignore")
        except Exception:
            out = proc.stdout

    items: List[Dict] = []
    try:
        reader = csv.DictReader(StringIO(out))
        for row in reader:
            try:
                rec = {
                    "TaskName": row.get("TaskName"),
                    "Next Run Time": row.get("Next Run Time"),
                    "Status": row.get("Status"),
                    "Last Run Time": row.get("Last Run Time"),
                    "Author": row.get("Author"),
                    "Task To Run": row.get("Task To Run"),
                }
                if state and (row.get("Status") or "") != state:
                    continue
                items.append(rec)
                if len(items) >= limit:
                    break
            except Exception:
                continue
    except Exception as e:
        items.append({"error": str(e)})
    return items
