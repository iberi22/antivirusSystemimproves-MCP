import platform
import re
import subprocess
from typing import Dict


def query_usn_info(drive: str = "C") -> Dict:
    """Consulta información del USN Journal vía 'fsutil usn queryjournal'.

    - drive: letra de unidad sin ':' (e.g., 'C')
    Devuelve dict con campos parseados o error si no disponible.
    """
    if platform.system() != "Windows":
        return {"error": "Solo disponible en Windows"}
    # Avoid invalid escape sequence warnings by escaping backslash
    drive = (drive or "C").rstrip(": /\\")
    cmd = ["fsutil", "usn", "queryjournal", f"{drive}:"]
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=False)
    except Exception as e:
        return {"drive": drive, "error": str(e)}
    if cp.returncode != 0:
        return {"drive": drive, "error": cp.stderr.strip() or cp.stdout.strip() or f"rc={cp.returncode}"}
    out = cp.stdout
    # Parse valores típicos
    data: Dict[str, str] = {"raw": out}
    patterns = {
        "Journal ID": r"Journal ID:\s*(\S+)",
        "First USN": r"First USN:\s*(\d+)",
        "Next USN": r"Next USN:\s*(\d+)",
        "Lowest Valid USN": r"Lowest Valid USN:\s*(\d+)",
        "Max USN": r"Max USN:\s*(\d+)",
        "Maximum Size": r"Maximum Size:\s*(\d+)",
        "Allocation Delta": r"Allocation Delta:\s*(\d+)",
    }
    for k, pat in patterns.items():
        m = re.search(pat, out)
        if m:
            data[k] = m.group(1)
    data["drive"] = drive
    return data
