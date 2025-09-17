# Guía del Agente Gemini CLI (Context-Aware Workflows)

Esta guía define el flujo de conciencia de contexto (context awareness) para el agente de código de Gemini CLI sobre este repositorio.

## Objetivo
- Operar el servidor MCP Windows Admin para diagnóstico, reputación y reporte.
- Seguir reglas globales de `docs/agents/SYSTEM_RULES.md` y convenciones POML en `docs/spec/POML_CONVENTIONS.md`.

## Paquete de contexto recomendado
Incluye estos paths (lectura):
- `README.md`
- `docs/spec/POML_CONVENTIONS.md`
- `docs/agents/SYSTEM_RULES.md`
- `docs/agents/GEMINI_CLI.md` (este archivo)
- `docs/AGENT_PROMPTS.md`
- `poml/*.poml`
- `.windsurf/workflows/*.md`
- `mcp_win_admin/` (interfaces de tools)
- `scripts/mcp_smoketest_stdio.py`

## Flujo de trabajo (alto nivel)
1. Cargar contexto (archivos arriba) y validar herramientas disponibles.
2. Ejecutar diagnóstico usando Inspector CLI (ver workflows).
3. Persistir salidas en `artifacts/` (JSON por tool).
4. Generar reporte HTML con `web/report/`.
5. Proponer acciones de mejora no destructivas y tareas siguientes.
6. Si el usuario lo autoriza, ejecutar workflows de defensa activos (separados).

## Prompts POML sugeridos
- Usa `poml/diagnostics.poml` para planear el diagnóstico.
- Usa `poml/report_html.poml` para ensamblar el reporte.
- Aplica `poml/guardrails.poml` siempre.

## Workflows listos para usar
- Diagnóstico: `/mcp-diagnostics` (auto-run)
- Reporte: ver `.windsurf/workflows/report-generate-and-serve.md`

## Referencia
- Blog “Gemini CLI: context-aware workflows & native diffing”. Úsalo como guía conceptual para empaquetar contexto y mantener un bucle iterativo con cambios en repo.
- Evita depender de sintaxis propietaria no documentada; usa POML + Markdown como capa interoperable.
