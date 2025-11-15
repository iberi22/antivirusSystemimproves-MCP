from __future__ import annotations
from typing import Any, Callable, Dict, List
from . import actions

# Definición de una acción de perfil como una función que puede ser ejecutada.
# El primer argumento de la función siempre debe ser `confirm: bool`.
ProfileAction = Callable[..., Dict[str, Any]]

PROFILES: Dict[str, Dict[str, ProfileAction]] = {
    "GameBooster": {
        "switch_power_plan": lambda confirm=False: actions.set_power_plan(
            actions.HIGH_PERFORMANCE_GUID, confirm=confirm
        ),
        "stop_non_essential_services": lambda confirm=False: actions.stop_service(
            "wuauserv", confirm=confirm  # Ejemplo: Windows Update
        ),
    },
    "Balanced": {},
    "AggressiveScan": {},
}

def list_profiles() -> List[Dict]:
    """Lista los perfiles disponibles y sus acciones."""
    return [
        {"name": name, "actions": list(actions.keys())}
        for name, actions in PROFILES.items()
    ]

def preview_profile(name: str) -> Dict:
    """Muestra una vista previa de las acciones de un perfil (sin ejecutarlas)."""
    profile_actions = PROFILES.get(name)
    if profile_actions is None:
        return {"name": name, "exists": False, "message": "Perfil no encontrado"}

    preview_results = [
        action(confirm=False) for action in profile_actions.values()
    ]
    return {
        "name": name,
        "exists": True,
        "summary": f"{len(preview_results)} acciones sugeridas (sin aplicar)",
        "actions": preview_results,
    }

def execute_profile_action(profile_name: str, action_key: str, confirm: bool = False) -> Dict:
    """Ejecuta una acción específica de un perfil."""
    if not confirm:
        return {"error": "Se requiere confirmación para ejecutar una acción."}

    profile_actions = PROFILES.get(profile_name)
    if profile_actions is None:
        return {"error": f"Perfil '{profile_name}' no encontrado."}

    action_to_run = profile_actions.get(action_key)
    if action_to_run is None:
        return {"error": f"Acción '{action_key}' no encontrada en el perfil '{profile_name}'."}

    return action_to_run(confirm=True)
