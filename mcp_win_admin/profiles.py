from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Dict, List


@dataclass
class ActionSuggestion:
    key: str
    description: str
    requires_elevation: bool = False

    def to_dict(self) -> Dict:
        return asdict(self)


# Perfiles iniciales de ejemplo (solo vista previa, no ejecutan cambios)
PROFILES: Dict[str, List[ActionSuggestion]] = {
    "GameBooster": [
        ActionSuggestion(
            key="stop_background_apps",
            description="Sugerir cierre de apps en segundo plano con alto consumo (previo análisis).",
        ),
        ActionSuggestion(
            key="switch_power_plan",
            description="Sugerir plan de energía Alto Rendimiento (sin aplicar automáticamente).",
            requires_elevation=False,
        ),
        ActionSuggestion(
            key="disable_unneeded_services",
            description="Sugerir deshabilitar servicios no críticos durante la sesión de juego (reversible).",
            requires_elevation=True,
        ),
    ],
    "Balanced": [
        ActionSuggestion(
            key="monitor_health",
            description="Monitorizar recursos y sugerir limpieza de disco temporal si es necesario.",
        )
    ],
}


def list_profiles() -> List[Dict]:
    return [
        {
            "name": name,
            "actions": [a.to_dict() for a in actions],
            "actions_count": len(actions),
        }
        for name, actions in PROFILES.items()
    ]


def preview_profile(name: str) -> Dict:
    actions = PROFILES.get(name)
    if not actions:
        return {
            "name": name,
            "exists": False,
            "message": "Perfil no encontrado",
        }
    return {
        "name": name,
        "exists": True,
        "summary": f"{len(actions)} acciones sugeridas (sin aplicar)",
        "actions": [a.to_dict() for a in actions],
        "security": {
            "requires_elevation": any(a.requires_elevation for a in actions),
            "notes": "Las acciones requieren consentimiento explícito antes de cualquier cambio.",
        },
    }
