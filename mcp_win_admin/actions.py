from __future__ import annotations
import subprocess
from typing import Dict, List

def stop_service(service_name: str, confirm: bool = False) -> Dict:
    """Detiene un servicio de Windows."""
    if not confirm:
        return {"action": "stop_service", "service": service_name, "status": "dryrun"}

    try:
        subprocess.run(["sc", "stop", service_name], check=True, capture_output=True, text=True)
        return {"action": "stop_service", "service": service_name, "status": "success"}
    except subprocess.CalledProcessError as e:
        return {"action": "stop_service", "service": service_name, "status": "error", "details": e.stderr}

def set_power_plan(plan_guid: str, confirm: bool = False) -> Dict:
    """Establece un plan de energía de Windows."""
    if not confirm:
        return {"action": "set_power_plan", "plan_guid": plan_guid, "status": "dryrun"}

    try:
        subprocess.run(["powercfg", "/setactive", plan_guid], check=True, capture_output=True, text=True)
        return {"action": "set_power_plan", "plan_guid": plan_guid, "status": "success"}
    except subprocess.CalledProcessError as e:
        return {"action": "set_power_plan", "plan_guid": plan_guid, "status": "error", "details": e.stderr}

# GUID para el plan de energía de "Alto Rendimiento" en Windows.
HIGH_PERFORMANCE_GUID = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
