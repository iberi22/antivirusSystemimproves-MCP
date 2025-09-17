from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]


def tool_run_diagnostics() -> Dict[str, Any]:
    """
    Ejecuta el diagnóstico MCP mediante Inspector CLI y guarda artefactos JSON en ./artifacts.
    Retorna un objeto con estado y mensaje.
    """
    ps1 = REPO_ROOT / "scripts" / "adk" / "run_diagnostics.ps1"
    try:
        rc = subprocess.call([
            "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ps1)
        ], cwd=str(REPO_ROOT))
        return {"status": "ok" if rc == 0 else "error", "code": rc}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def tool_prepare_report() -> Dict[str, Any]:
    """Copia ./artifacts a web/report/artifacts para su visualización."""
    ps1 = REPO_ROOT / "scripts" / "adk" / "prepare_report.ps1"
    try:
        rc = subprocess.call([
            "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ps1)
        ], cwd=str(REPO_ROOT))
        return {"status": "ok" if rc == 0 else "error", "code": rc}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def build_agents() -> Dict[str, Any]:
    """
    Devuelve instancias de agentes ADK code-first (requiere `google-adk`).

    Ejemplo de uso:
        from adk_agents.windows import build_agents
        agents = build_agents()
        root = agents["coordinator"]
        result = root.run({"task": "Run diagnostics and prepare report"})
    """
    try:
        from google.adk.agents import Agent
    except Exception as e:
        raise RuntimeError(
            "google-adk no está instalado. Instala con: pip install google-adk"
        ) from e

    diagnostics_agent = Agent(
        name="windows_diagnostics_agent",
        model="gemini-2.0-flash",
        instruction=(
            "Eres un agente de diagnóstico de Windows. Ejecuta herramientas MCP de diagnóstico de forma "
            "no destructiva y reporta resultados sintetizados."
        ),
        tools=[tool_run_diagnostics],
        description="Recolecta artefactos JSON de diagnóstico usando Inspector CLI y MCP",
    )

    reporting_agent = Agent(
        name="windows_reporting_agent",
        model="gemini-2.0-flash",
        instruction=(
            "Eres un agente de reporte. Preparas el reporte web local copiando artifacts al destino."
        ),
        tools=[tool_prepare_report],
        description="Prepara el reporte web a partir de artifacts JSON",
    )

    coordinator = Agent(
        name="windows_coordinator",
        model="gemini-2.0-flash",
        instruction=(
            "Coordina diagnóstico y preparación de reporte. Respeta guardrails no destructivos."
        ),
        sub_agents=[diagnostics_agent, reporting_agent],
        description="Coordina agentes de diagnóstico y reporte",
    )

    return {
        "diagnostics": diagnostics_agent,
        "reporting": reporting_agent,
        "coordinator": coordinator,
    }
