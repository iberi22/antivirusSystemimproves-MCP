# mcp-windows-admin (Antivirus/GameBooster)

Servidor MCP en Python para administración y mejora de Windows con enfoque Antivirus/GameBooster.

- Expone herramientas (tools) MCP de diagnóstico y gestión segura.
- Soporta perfiles (p.ej. GameBooster) para automatizar acciones con confirmación.
- Persiste snapshots y hallazgos en SQLite para contrastar estados y detectar anomalías.

## Requisitos

- Windows 10/11
- Python 3.10+

## Instalación (modo desarrollador)

```powershell
# Opcional: crear entorno virtual
python -m venv .venv
.\.venv\Scripts\activate

# Instalar en editable con dependencias
pip install -e ".[dev]"
```

## Ejecutar el servidor MCP (inspector/dev)

Puedes probar el servidor con el Inspector de MCP del SDK oficial.

```powershell
# Instalar el CLI del SDK (si no lo tienes)
python -m pip install "mcp[cli]"
# Alternativa con uv: uv add "mcp[cli]"

# Modo desarrollo con el Inspector (pip)
mcp dev .\mcp_win_admin\server.py --with-editable .
# Alternativa (módulo)
python -m mcp dev .\mcp_win_admin\server.py --with-editable .
```

También puedes instalarlo en clientes compatibles (Windsurf/Cascade, Claude Desktop, etc.) registrando la ruta al script `server.py`.

## Características (MVP)

- Tools de lectura segura:
  - `system_scan_performance` – CPU, memoria, disco, uptime; guarda snapshot en SQLite.
  - `processes_list` – Lista procesos (CPU/Mem top).
  - `services_list` – (placeholder) Próxima iteración.
  - `logs_query_eventlog` – (placeholder) Próxima iteración.
- Perfiles:
  - `profiles_list` – Lista perfiles, incluyendo "AggressiveScan".
  - `profiles_preview` – Muestra acciones sugeridas (p.ej. GameBooster, AggressiveScan) sin ejecutarlas.
- SQLite (WAL):
  - Snapshots de sistema y hallazgos para comparar estados.

## Antivirus y Reputación

- Fuentes soportadas para hashes: `malwarebazaar`, `teamcymru` (MHR).
  - `teamcymru` (MHR) funciona vía DNS. No requiere API key. Veredicto "malicious" si responde 127.0.0.2.
  - `malwarebazaar` es gratuita y no requiere API key.
  - Soporte adicional de reputación de red y dominios: `otx` (AlienVault), `greynoise`, `abuseipdb`.
- Ejemplos de uso (Inspector MCP):
  - `av_check_hash(hash_hex, sources_csv="malwarebazaar,teamcymru")`
  - `av_scan_path(target, use_cloud=true, sources_csv="malwarebazaar,teamcymru", ttl_seconds=86400)`
  - Para incluir `virustotal`, añade `sources_csv="virustotal,malwarebazaar,teamcymru"` y configura `VT_API_KEY`.

### Reputación de IP/Dominio

- Tools:
  - `rep_check_ip(ip, sources_csv="threatfox,urlhaus", ttl_seconds=86400[, ttl_by_source_json])`
  - `rep_check_domain(domain, sources_csv="threatfox,urlhaus", ttl_seconds=86400[, ttl_by_source_json])`
  - Conexiones enriquecidas:
  - `connections_list_enriched(limit=100, rep_sources_csv="threatfox,urlhaus"[, rep_ttl_by_source_json])`
- Puedes añadir `virustotal`, `otx`, `greynoise`, `abuseipdb` si cuentas con sus API keys.

#### TTL por fuente (granular)

- Además de `ttl_seconds`, puedes especificar TTLs por fuente:

  ```json
  {
    "virustotal": 86400,
    "otx": 43200,
    "greynoise": 21600,
    "abuseipdb": 7200
  }
  ```

- Ejemplos:

  ```text
  rep_check_ip("1.2.3.4", ttl_seconds=86400, ttl_by_source_json='{"greynoise": 3600, "abuseipdb": 7200}')
  connections_list_enriched(limit=50, rep_ttl_by_source_json='{"virustotal": 86400, "otx": 3600}')
  ```

#### Variables de entorno (reputación)

- `VT_API_KEY`: API key de VirusTotal (opcional, recomendado).
- `OTX_API_KEY`: API key de AlienVault OTX (opcional).
- `GREYNOISE_API_KEY`: API key de GreyNoise (Community/Enterprise) (opcional).
- `ABUSEIPDB_API_KEY`: API key de AbuseIPDB (opcional).
- `MCP_FREE_ONLY_SOURCES`: si es `true` (por defecto), se usan solo fuentes gratuitas por defecto. Ponlo en `false` para permitir que las tools amplíen automáticamente a fuentes que requieren API key cuando no personalizas `sources_csv`.

Notas:

- Por defecto priorizamos fuentes gratuitas (ThreatFox/URLHaus, MalwareBazaar/TeamCymru). Para incluir fuentes que requieren API key (VirusTotal/OTX/GreyNoise/AbuseIPDB), añádelas explícitamente en `sources_csv` y define sus variables de entorno.
- Existe caché local en SQLite con TTL global y por fuente. Si `ttl_seconds` es negativo, se ignora el TTL global y se usa lo disponible; si es 0 o mayor, sólo se consideran entradas frescas.
- Si se provee `ttl_by_source_json`, se aplica por fuente (y el global queda como fallback para fuentes no listadas).

#### Configuración sample para Windsurf

- Archivo de ejemplo: `configs/windsurf.mcp.json`
- Define el servidor MCP por `stdio` con Python y variables de entorno recomendadas (modo ligero).
- En Windsurf/Cascade, importa ese JSON y ajusta rutas/env según tu entorno.
- Por defecto activa `MCP_FREE_ONLY_SOURCES=true`. Si quieres incluir fuentes de pago globalmente, edita el JSON y cambia a `false`.

## Defensa activa (real)

- Tools (ejecución controlada, requieren `confirm=true`):
  - `defense_quarantine_execute(path, confirm=false, policy_name="Strict")`
  - `defense_kill_process_execute(pid, confirm=false, policy_name="Strict")`

- Políticas:
  - `Strict` (por defecto): protege PIDs críticos y procesos del sistema, límite 100 MB en cuarentena.
  - `Balanced`: protege sistema, límite 256 MB.
  - `Aggressive`: permite actuar sobre sistema, límite 1 GB. Úsala con extremo cuidado.

- Cuarentena:
  - Los archivos se mueven a `~/.mcp_win_admin/quarantine/` con nombre `timestamp__sha12__archivo` y manifiesto `*.manifest.json` con `sha256`, política y fecha.

- Seguridad:
  - Todas las acciones reales requieren `confirm=true`.
  - Auditoría vía `db.log_event()` en SQLite.

Ejemplos:

```text
defense_quarantine_execute(path="C:\\sospechoso.bin", confirm=true, policy_name="Strict")
defense_kill_process_execute(pid=1234, confirm=true, policy_name="Balanced")
```

## Alertas y notificaciones

- Tools:
  - `alert_notify_webhook(event, level="INFO", data_json="{}", url="")`
  - `alert_notify_toast(title, message)` (best‑effort, requiere `win10toast` o `winrt` si disponible)

- Variables de entorno:
  - `ALERT_WEBHOOK_URL`: si no se pasa `url`, se usa este valor para enviar eventos automáticos (por ejemplo, tras cuarentena o kill).

Ejemplos:

```text
alert_notify_webhook(event="quarantine_executed", level="INFO", data_json='{"path":"C:\\sospechoso.bin"}', url="https://mi.webhook")
alert_notify_toast(title="MCP", message="Amenaza mitigada")
```

## YARA (opcional)

- Instalación opcional: `pip install -e ".[yara]"` o `pip install yara-python`.
- Tools:
  - `yara_scan_path(target, rules_path=..., recursive=true)`
  - `yara_test_rule(rule_text, sample_path)`
  - Soporta carpeta o archivo de reglas (`.yar`/`.yara`).

## USN Journal (solo Windows/NTFS)

- Tool: `usn_query_info(drive="C")`
- Nota: puede requerir consola elevada (Administrador) y la unidad debe ser NTFS.

## Seguridad

- Por defecto, solo lectura. Acciones que cambian el sistema requieren confirmación explícita y, si aplica, elevación UAC.
- Auditoría: logs estructurados y (próximamente) Event Log.

## Pruebas automatizadas

- Requisitos dev: `pytest`, `pytest-asyncio`, `ruff`, `mypy`, `fastmcp` (en extras `dev`).

Instalación y ejecución:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -U pip
.venv\Scripts\python -m pip install -e .[dev]
.venv\Scripts\pytest -q
```

La suite incluye:

- Tests unitarios de DB, antivirus, reputación y defensa activa bajo `tests/`.
- Test de integración MCP con `fastmcp.Client` en memoria (`tests/test_mcp_client_tools.py`):
  - Lista tools y recursos expuestos por `mcp_win_admin/server.py`.
  - Ejecuta tools claves (`system_scan_performance`, `db_optimize`, `db_purge_old`).
  - Lee el recurso `snapshot://last`.

## Pruebas del protocolo MCP (manuales/CLI)

- FastMCP Client (programático, Python): ver `tests/test_mcp_client_tools.py` para ejemplo mínimo de cliente en memoria.

- Inspector CLI (Node):

  Requiere Node.js. Inicia el servidor por `stdio` y conecta el Inspector:

  ```bash
  npx -y @modelcontextprotocol/inspector python -m mcp_win_admin.server
  ```

  Desde la UI/CLI podrás listar tools/recursos y ejecutar llamadas.

- Alternativas CLI:
  - `mcptools` (CLI de terceros): <https://github.com/f/mcptools>
  - `mcp-cli` (proyecto comunitario): <https://github.com/chrishayuk/mcp-cli>

Sugerencia CI: integrar una job opcional que ejecute el test de cliente FastMCP (sin Node) y otra job que instale Node y ejecute Inspector CLI contra `python -m mcp_win_admin.server` para validar stdio.

## Mantenimiento y limpieza de base de datos

- Modo WAL, índices específicos y PRAGMAs seguros para rendimiento bajo carga.
- Hilo de mantenimiento en segundo plano (daemon) configurable por variables de entorno.

Tools:

- `db_optimize()` – Ejecuta `PRAGMA optimize` y `wal_checkpoint(PASSIVE)` para compactar y mejorar planes.
- `db_purge_old(events_ttl_seconds=-1, reputation_ttl_seconds=-1, hash_ttl_seconds=-1)` – Purga datos antiguos:
  - Eventos (`events.ts_utc`)
  - Reputación global y por fuente (`last_seen`)
  - Veredictos de hashes (`last_seen`)

Variables de entorno (mantenimiento):

- `MCP_DB_MAINT_ENABLED` (bool, por defecto `true`): activa el hilo de mantenimiento.
- `MCP_DB_MAINT_ON_START` (bool, por defecto `true`): ejecuta mantenimiento inmediato al iniciar.
- `MCP_DB_MAINT_INTERVAL_SECONDS` (int, por defecto `21600` = 6h): intervalo entre ciclos.
- `MCP_DB_PURGE_EVENTS_TTL_SECONDS` (int, por defecto `-1`): TTL para purgar eventos. `-1` desactiva.
- `MCP_DB_PURGE_REP_TTL_SECONDS` (int, por defecto `-1`): TTL para purgar reputación (global y por fuente). `-1` desactiva.
- `MCP_DB_PURGE_HASH_TTL_SECONDS` (int, por defecto `-1`): TTL para purgar veredictos de hashes. `-1` desactiva.

Ejemplos (Inspector MCP):

```text
db_optimize()
db_purge_old(events_ttl_seconds=2592000, reputation_ttl_seconds=7776000, hash_ttl_seconds=15552000)
```

Notas:

- `wal_checkpoint(PASSIVE)` no bloquea escritores y limita el crecimiento del WAL.
- Índices en `last_seen` y `ts_utc` aceleran purgas y consultas.
- En modo ligero, los TTL efectivos para consultas de reputación se controlan con `MCP_DEFAULT_REP_TTL` y `ttl_by_source_json` en las tools.

## Roadmap

- Acciones controladas: servicios, paquetes (winget/Chocolatey), ficheros (sandbox), limpieza segura.
- Logs/ETW/Sysmon.
- Exportación OpenTelemetry.
- Empaquetado opcional (PyInstaller/MSI) para usuarios finales.

## Estado de cobertura y calidad

- Cobertura por módulos críticos:
  - `defense.py`: 100%
  - `updates.py`: 100%
  - `av.py`, `reputation.py`, `tasks.py`, `system.py`, `db.py`: 100% (según última ejecución de la suite)
- CI en Windows (GitHub Actions) ejecuta `pytest + coverage` para validar cambios.
- Ejecuta cobertura local:

```powershell
.venv\Scripts\pytest -q --cov=mcp_win_admin --cov-report=term-missing
```

## Guía rápida (cheat‑sheet)

- Iniciar servidor MCP (Inspector):

```powershell
mcp dev .\mcp_win_admin\server.py --with-editable .
```

- Antivirus y reputación:
  - `av_check_hash(hash_hex, sources_csv="malwarebazaar,teamcymru")`
  - `av_scan_path(target, use_cloud=true, sources_csv="malwarebazaar,teamcymru", ttl_seconds=86400)`
  - `rep_check_ip("1.2.3.4", ttl_seconds=86400, ttl_by_source_json='{"greynoise": 3600, "abuseipdb": 7200}')`
  - `connections_list_enriched(limit=50, rep_ttl_by_source_json='{"virustotal": 86400, "otx": 3600}')`

- Defensa activa (confirmación obligatoria):
  - `defense_quarantine_execute(path="C:\\sospechoso.bin", confirm=true, policy_name="Strict")`
  - `defense_kill_process_execute(pid=1234, confirm=true, policy_name="Balanced")`
  - `process_isolate_execute(pid=1234, confirm=true, policy_name="Strict")`
  - `process_unsandbox_execute(pid=1234, confirm=true)`

- Mantenimiento BD:
  - `db_optimize()`
  - `db_purge_old(events_ttl_seconds=2592000, reputation_ttl_seconds=7776000, hash_ttl_seconds=15552000)`

- Ejecución de Perfiles:
  - `profiles_execute(profile_name="GameBooster", action_key="switch_power_plan", confirm=true)`

- Escaneo Moderno (con motor de Rust):
  - `av_scan_path_modern(target, use_behavioral_scan=true)`
  - `behavioral_scan()`

- Modo ligero (variables recomendadas):
  - `MCP_LIGHT_MODE=true`
  - `MCP_DEFAULT_REP_TTL=86400`
  - `MCP_DB_MAINT_ENABLED=true`, `MCP_DB_MAINT_INTERVAL_SECONDS=21600`
  - `MCP_FREE_ONLY_SOURCES=true` (por defecto). Para incluir fuentes pagas de forma global: `MCP_FREE_ONLY_SOURCES=false` (o especifica explícitamente en `sources_csv`).

Más ejemplos y prompts de integración para agentes: ver `docs/AGENT_PROMPTS.md`.

## Licencia

MIT (propuesta).
