# Reglas del Sistema Agéntico (Windows Admin / Antivirus / Optimización)

Estas reglas aplican a agentes de código (Gemini CLI, Cascade/Windsurf, etc.) que operan este repositorio.

## Principios
- Prioriza seguridad, reproducibilidad y mínima intrusión.
- Idioma por defecto: Español.
- Usa MCP Windows Admin como capa de herramientas del sistema.
- Sigue las convenciones POML del proyecto: `docs/spec/POML_CONVENTIONS.md`.

## Permisos y seguridad
- Acciones por defecto: diagnósticas y no destructivas.
- Acciones destructivas (kill/quarantine/firewall) requieren confirmación explícita del usuario y deben estar en workflows separados.
- Respeta límites: `limit`, `fast`, `include_cpu`, `listening_only` y TTLs de reputación.
- No eleves privilegios; reporta accesos denegados con mensajes claros.

## Artefactos y reporte
- Guarda salidas JSON en `artifacts/`. Nombra por herramienta: `processes_memory.json`, `connections.json`, etc.
- Genera reportes visuales con la plantilla `web/report/`.
- Vincula hallazgos a evidencias (archivos JSON) y a comandos exactos utilizados.

## Fuentes de reputación TI (cacheadas)
- OTX, GreyNoise, AbuseIPDB, ThreatFox, URLHaus, MalwareBazaar, TeamCymru. Ver `.env` y README para API keys.

## Herramientas MCP relevantes (nombres de tool)
- `system_scan_performance`
- `processes_list`
- `connections_list_enriched`
- `startup_list`, `tasks_list`, `services_list`, `events_list`
- `av_scan_path`
- `rep_check_ip`, `rep_check_domain`
- `rootkit_check_port_owners`, `rootkit_detect_hidden_processes`
- `fs_top_dirs`, `updates_list_installed`, etc.

## Workflows
- Diagnóstico: `.windsurf/workflows/mcp-diagnostics.md` (auto-run)
- Reporte HTML: `.windsurf/workflows/report-generate-and-serve.md`

## POML de referencia
- `poml/diagnostics.poml`: plan de diagnóstico y outputs esperados.
- `poml/report_html.poml`: plan para construir reporte visual.
- `poml/guardrails.poml`: restricciones de seguridad.
