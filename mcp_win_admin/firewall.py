import subprocess
from typing import Dict, List


def list_rules(limit: int = 500) -> List[Dict]:
    cmd = ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]
    try:
        out = subprocess.check_output(cmd, shell=False, text=True, stderr=subprocess.STDOUT, timeout=15)
    except Exception as e:
        return [{"error": str(e)}]
    items: List[Dict] = []
    cur: Dict[str, str] = {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("Rule Name:") or line.startswith("Nombre de regla:"):
            if cur:
                items.append(cur)
                if len(items) >= limit:
                    break
            cur = {"name": line.split(":", 1)[1].strip()}
        else:
            if ":" in line:
                k, v = line.split(":", 1)
                cur[k.strip().lower().replace(" ", "_")] = v.strip()
    if cur and len(items) < limit:
        items.append(cur)
    return items


def export_rules(file_path: str) -> Dict:
    cmd = ["netsh", "advfirewall", "export", file_path]
    try:
        out = subprocess.check_output(cmd, shell=False, text=True, stderr=subprocess.STDOUT, timeout=20)
        return {"ok": True, "output": out}
    except Exception as e:
        return {"error": str(e)}


def block_ip_dryrun(ip: str) -> Dict:
    cmd = f"netsh advfirewall firewall add rule name=Block_{ip} dir=out action=block remoteip={ip}"
    return {"dryrun": True, "command": cmd}
