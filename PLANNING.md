# PLANNING.md — MCP Windows Admin (Antivirus/GameBooster)

## Visión y Objetivo
Construir un servidor MCP en Python para administración profunda y segura de Windows, con enfoque en:
- Diagnóstico y observabilidad (procesos, rendimiento, discos, eventos).
- Perfiles y tareas de optimización (p.ej., GameBooster) con consentimiento del usuario.
- Arquitectura abierta, auditable y extensible por la comunidad.

## Principios y Restricciones
- Transparencia, no intrusivo, y evitar patrones de malware.
- Acciones que modifiquen el sistema requieren aprobación explícita (y elevación UAC si aplica).
- Sin persistencia stealth. Registro claro de acciones y logs.
- Distribución open-source; ejecución directa (sin MSI) en fase inicial.
- Compatibilidad: Windows 10/11, Python 3.10+.

## Arquitectura de Alto Nivel
- Cliente/Host (IDE/Agente LLM) ↔ Servidor MCP (FastMCP) ↔ Módulos de sistema (psutil, WMI, Win32)
- Servidor MCP (Python):
  - Tools (acciones): `system_scan_performance`, `processes_list`, `profiles_list`, `profiles_preview`.
  - Resources (datos): `snapshot://last` (último snapshot persistido).
  - Seguridad: scopes por tool, mensajes de confirmación para acciones futuras que modifiquen el sistema.
- Persistencia local: SQLite (WAL) en `%USERPROFILE%/.mcp_win_admin/state.sqlite3`.
- Auditoría: tabla `events`, logs legibles y (futuro) Event Log de Windows.

## Módulos y Responsabilidades
- `mcp_win_admin/server.py`: registro FastMCP, tools y recurso, arranque `mcp.run()`.
- `mcp_win_admin/system.py`: snapshots de rendimiento (CPU, Mem, Disco, Uptime, Procesos).
- `mcp_win_admin/processes.py`: listado de procesos con métricas (PID, RSS, CPU%).
- `mcp_win_admin/db.py`: SQLite (init, insert/get snapshot, log_event) con soporte de ruta.
- `mcp_win_admin/profiles.py`: perfiles declarativos (GameBooster, Balanced) y previsualización.

## Seguridad y Privacidad
- Por defecto, herramientas de solo lectura.
- Acciones que cambien estado: diseñadas para requerir confirmación explícita y posible elevación UAC por tool.
- Evitar recoger PII innecesaria. Datos locales por defecto, sin exfiltración.

## Stack Tecnológico
- Lenguaje: Python 3.10+
- MCP SDK: `mcp[cli]` (FastMCP)
- Windows Integration: `psutil`, `pywin32`, `wmi`
- Tests: `pytest`
- Calidad: `ruff`, `mypy` (configurados en `pyproject.toml`)

## Roadmap (alto nivel)
- MVP (actual): servidor + herramientas read-only + SQLite + perfiles (preview) ✔
- Iteración 2: servicios (listar y estado), consulta básica de Event Log.
- Iteración 3: acciones controladas de GameBooster (con consentimiento y reversibilidad).
- Iteración 4: Telemetría avanzada (ETW/Sysmon), OTel opcional.
- Empaquetado opcional (PyInstaller/MSI) para usuarios finales.

## Decisiones Clave
- Python-first por facilidad y adopción open-source; potencial migración parcial a Rust/.NET para binarios firmados en futuro.
- SQLite WAL local para trazabilidad y comparación de estados.
- Modelo de elevación puntual (no servicio residente) para minimizar superficie de ataque.

## Prompt para IA (Reglas del Proyecto)
- Usa la estructura y decisiones de este archivo como referencia inicial.
- Antes de implementar nuevas features, agrega/actualiza tareas en `TASK.md`.
- Mantén módulos pequeños (<500 líneas) y con responsabilidades claras.
