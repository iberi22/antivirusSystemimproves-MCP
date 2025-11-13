# PLANNING.md — MCP Windows Admin (Antivirus/GameBooster)

## Visión y Objetivo
Construir un servidor MCP en Python para administración profunda y segura de Windows, con enfoque en:
- Diagnóstico y observabilidad (procesos, rendimiento, discos, eventos).
- Perfiles y tareas de optimización (p.ej., GameBooster) con consentimiento del usuario.
- Arquitectura abierta, auditable y extensible por la comunidad, con componentes de alto rendimiento en Rust.

## Principios y Restricciones
- Transparencia, no intrusivo, y evitar patrones de malware.
- Acciones que modifiquen el sistema requieren aprobación explícita (y elevación UAC si aplica).
- Sin persistencia stealth. Registro claro de acciones y logs.
- Distribución open-source; ejecución directa (sin MSI) en fase inicial.
- Compatibilidad: Windows 10/11, Python 3.10+.

## Arquitectura de Alto Nivel
- Cliente/Host (IDE/Agente LLM) ↔ Servidor MCP (FastMCP) ↔ Módulos de sistema (psutil, WMI, Win32)
- Servidor MCP (Python):
  - Tools (acciones): `system_scan_performance`, `processes_list`, `profiles_list`, `profiles_preview`, `av_scan_path_modern`, `behavioral_scan`.
  - Resources (datos): `snapshot://last` (último snapshot persistido).
  - Seguridad: scopes por tool, mensajes de confirmación para acciones futuras que modifiquen el sistema.
- Motor de Escaneo (Rust):
  - Módulo nativo (`native_scanner`) para escaneo de archivos en paralelo y cálculo de hashes.
  - Interfaz con Python a través de `PyO3`.
- Persistencia local: SQLite (WAL) en `%USERPROFILE%/.mcp_win_admin/state.sqlite3`.
- Auditoría: tabla `events`, logs legibles y (futuro) Event Log de Windows.

## Módulos y Responsabilidades
- `mcp_win_admin/server.py`: registro FastMCP, tools y recurso, arranque `mcp.run()`.
- `mcp_win_admin/system.py`: snapshots de rendimiento (CPU, Mem, Disco, Uptime, Procesos).
- `mcp_win_admin/processes.py`: listado de procesos con métricas (PID, RSS, CPU%).
- `mcp_win_admin/db.py`: SQLite (init, insert/get snapshot, log_event) con soporte de ruta.
- `mcp_win_admin/profiles.py`: perfiles declarativos (GameBooster, Balanced, AggressiveScan) y previsualización.
- `mcp_win_admin/scanner.py`: puente entre Python y el módulo nativo de Rust.
- `mcp_win_admin/behavioral.py`: lógica para la detección de amenazas basada en el comportamiento.
- `native/native_scanner`: módulo de Rust para escaneo de archivos en paralelo.

## Seguridad y Privacidad
- Por defecto, herramientas de solo lectura.
- Acciones que cambien estado: diseñadas para requerir confirmación explícita y posible elevación UAC por tool.
- Evitar recoger PII innecesaria. Datos locales por defecto, sin exfiltración.

## Stack Tecnológico
- Lenguaje: Python 3.10+, Rust 2021+
- MCP SDK: `mcp[cli]` (FastMCP)
- Windows Integration: `psutil`, `pywin32`, `wmi`
- Python-Rust Bridge: `PyO3`, `setuptools-rust`
- Tests: `pytest`
- Calidad: `ruff`, `mypy` (configurados en `pyproject.toml`)

## Roadmap (alto nivel)
- MVP: servidor + herramientas read-only + SQLite + perfiles (preview) ✔
- Iteración 2: Escáner de archivos en paralelo con Rust y detección de comportamiento. ✔
- Iteración 3: servicios (listar y estado), consulta básica de Event Log.
- Iteración 4: acciones controladas de GameBooster (con consentimiento y reversibilidad).
- Iteración 5: Telemetría avanzada (ETW/Sysmon), OTel opcional.
- Empaquetado opcional (PyInstaller/MSI) para usuarios finales.

## Decisiones Clave
- Híbrido Python/Rust para combinar facilidad de desarrollo con alto rendimiento.
- SQLite WAL local para trazabilidad y comparación de estados.
- Modelo de elevación puntual (no servicio residente) para minimizar superficie de ataque.

## Prompt para IA (Reglas del Proyecto)
- Usa la estructura y decisiones de este archivo como referencia inicial.
- Antes de implementar nuevas features, agrega/actualiza tareas en `TASK.md`.
- Mantén módulos pequeños (<500 líneas) y con responsabilidades claras.
