# Integración con Gemini CLI ADK (Context-Aware Agent)

Este documento explica cómo mapear este repositorio a un agente basado en el ADK de Gemini CLI para lograr flujos contextuales (diagnóstico → artefactos → reporte) respetando nuestras convenciones POML y reglas de seguridad.

## Componentes de contexto (incluir en el pack)
- `README.md`
- `docs/spec/POML_CONVENTIONS.md`
- `docs/agents/SYSTEM_RULES.md`
- `docs/agents/GEMINI_CLI.md`
- `docs/agents/GEMINI_ADK.md` (este)
- `docs/AGENT_PROMPTS.md`
- `poml/diagnostics.poml`, `poml/report_html.poml`, `poml/guardrails.poml`
- `.windsurf/workflows/*.md` (como referencia de comandos exactos)
- `mcp_win_admin/` (definición de herramientas)
- `scripts/mcp_smoketest_stdio.py` (prueba rápida SDK oficial)
- `web/report/` (plantilla del reporte)

## Acciones/Skills recomendadas (shell)
Registra acciones (skills) que llamen a estos scripts PowerShell. Son no destructivas y reproducibles.

- `adk:diagnostics:run`
  - Ejecuta diagnóstico completo MCP y guarda JSON en `artifacts/`.
  - Script: `scripts/adk/run_diagnostics.ps1`
- `adk:report:prepare`
  - Copia `artifacts/` a `web/report/artifacts/`.
  - Script: `scripts/adk/prepare_report.ps1`
- `adk:report:serve`
  - Sirve `web/report/` en `http://localhost:5500`.
  - Script: `scripts/adk/serve_report.ps1`

Estas tres acciones implementan el objetivo del agente: observar → razonar (POML) → actuar (ejecutar diagnóstico) → comunicar (reporte web).

## Mapeo a POML
- Planeación: `poml/diagnostics.poml` (qué correr, qué outputs producir)
- Reporte: `poml/report_html.poml` (cómo ensamblar el reporte con artifacts)
- Guardrails: `poml/guardrails.poml` (seguridad por defecto no destructiva)

El agente debe inyectar estas POML como prompts de sistema/contexto para guiar la toma de decisiones y el formato de entrega.

## Parámetros y entorno
- Requiere `node`/`npx` y un venv en `.venv`.
- Variables opcionales: API keys de OTX, GreyNoise, AbuseIPDB (véase README).
- Los scripts autodetectan rutas `Downloads` y `Temp` via `$env:USERPROFILE`/`$env:TEMP`.

## Flujo estándar del agente (alto nivel)
1. Cargar contexto (sección "Componentes de contexto").
2. Aplicar guardrails POML.
3. Ejecutar `adk:diagnostics:run`.
4. Ejecutar `adk:report:prepare`.
5. Ejecutar `adk:report:serve` y devolver URL al usuario.
6. Proponer acciones de mejora; separar defensas activas en skills distintos que pidan confirmación.

## Notas sobre Windsurf/Cascade
- En Windsurf ya existen workflows equivalentes (`/mcp-diagnostics` y `/report-generate-and-serve`) con auto-run.
- ADK puede usar estos scripts para lograr lo mismo fuera de Windsurf, manteniendo una interfaz idéntica.
