# Guía de Prompts para Agentes (MCP Windows Admin)

Esta guía te ofrece prompts y patrones para que agentes (LLMs/code agents) interactúen con el servidor MCP `mcp_win_admin/server.py` de forma segura y eficaz.

- Cliente sugerido para pruebas: Inspector MCP (`mcp dev`) o FastMCP Client (Python).
- Reglas clave:
  - Evita acciones destructivas sin confirmación explícita (`confirm=true`).
  - Prefiere primero consultas/dry-run antes de ejecutar.
  - Limita resultados (p. ej., `limit=50`) y usa TTL/caché en reputación.

---

## Descubrimiento y estado

- Listar tools y recursos expuestos:

```text
list_tools()
list_resources()
```

- Leer último snapshot:

```text
read_resource("snapshot://last")
```

---

## Rendimiento y procesos

- Estado de rendimiento y snapshot:

```text
system_scan_performance()
```

- Listar procesos (rápido, con métricas clave):

```text
processes_list(include_cpu=true, include_memory=true, limit=50)
```

Sugerencia: filtra por `name` o `exe` en el cliente para foco.

---

## Antivirus y reputación

- Comprobar hash con múltiples fuentes (sin API):

```text
av_check_hash(hash_hex, sources_csv="malwarebazaar,teamcymru")
```

- Escanear un path con cloud (requiere `VT_API_KEY` si usas `virustotal`):

```text
av_scan_path(target, use_cloud=true, sources_csv="virustotal,malwarebazaar,teamcymru", ttl_seconds=86400)
```

- Reputación IP con TTL por fuente:

```text
rep_check_ip("1.2.3.4", ttl_seconds=86400, ttl_by_source_json='{"greynoise":3600,"abuseipdb":7200}')
```

- Reputación de dominio:

```text
rep_check_domain("example.com", ttl_seconds=86400)
```

- Conexiones enriquecidas (con reputación integrada):

```text
connections_list_enriched(limit=50, rep_ttl_by_source_json='{"virustotal":86400,"otx":3600}')
```

Buenas prácticas:
- Usa `ttl_by_source_json` para fuentes ruidosas/costosas.
- El módulo ya cachea veredictos en SQLite para evitar llamadas repetidas.

---

## Defensa activa (confirmación requerida)

Siempre valida impacto y política antes de ejecutar. Opciones de `policy_name`: `Strict` (por defecto), `Balanced`, `Aggressive`.

- Cuarentena de archivo:

```text
defense_quarantine_execute(path="C:\\sospechoso.bin", confirm=true, policy_name="Strict")
```

- Terminar/Killar proceso:

```text
defense_kill_process_execute(pid=1234, confirm=true, policy_name="Balanced")
```

- Aislar proceso (firewall + prioridad/afinidad):

```text
process_isolate_execute(pid=1234, confirm=true, policy_name="Strict")
```

- Revertir aislamiento:

```text
process_unsandbox_execute(pid=1234, confirm=true)
```

Dry-run sugerido antes de ejecutar:

```text
kill_process_dryrun(pid)
quarantine_dryrun(path)
process_isolate_dryrun(pid)
```

---

## Alertas y notificaciones

- Webhook (usa `ALERT_WEBHOOK_URL` si `url` vacío):

```text
alert_notify_webhook(event="quarantine_executed", level="INFO", data_json='{"path":"C:\\sospechoso.bin"}')
```

- Toast local (best-effort, Windows):

```text
alert_notify_toast(title="MCP", message="Amenaza mitigada")
```

---

## Mantenimiento de base de datos

- Optimización:

```text
db_optimize()
```

- Purgado de datos antiguos:

```text
db_purge_old(events_ttl_seconds=2592000, reputation_ttl_seconds=7776000, hash_ttl_seconds=15552000)
```

---

## Variables de entorno recomendadas

Configúralas antes de iniciar el servidor para un modo de operación eficiente:

```powershell
# Modo ligero y mantenimiento
$env:MCP_LIGHT_MODE = "true"
$env:MCP_DEFAULT_REP_TTL = "86400"
$env:MCP_DB_MAINT_ENABLED = "true"
$env:MCP_DB_MAINT_INTERVAL_SECONDS = "21600"

# API keys (opcional)
$env:VT_API_KEY = "..."
$env:OTX_API_KEY = "..."
$env:GREYNOISE_API_KEY = "..."
$env:ABUSEIPDB_API_KEY = "..."

# Webhook de alertas (opcional)
$env:ALERT_WEBHOOK_URL = "https://tu-webhook"
```

---

## Flujos recomendados (prompt chains)

- Investigación de proceso sospechoso:

```text
1) processes_list(limit=50)
2) connections_list_enriched(limit=50)
3) rep_check_ip para IPs externas vistas (usa ttl_by_source_json)
4) av_scan_path(exe del proceso)
5) Si veredicto probable malicioso, sugiere: process_isolate_dryrun(pid)
6) Con confirmación del usuario: process_isolate_execute(pid, confirm=true)
7) Notifica por webhook (alert_notify_webhook)
```

- Respuesta a archivo detectado:

```text
1) av_check_hash(hash_hex)
2) quarantine_dryrun(path)
3) Si política y tamaño lo permiten, con confirm: defense_quarantine_execute(path, confirm=true)
4) Registrar evento via webhook
```

- Mantenimiento programado:

```text
1) db_optimize()
2) db_purge_old(events_ttl_seconds=2592000, reputation_ttl_seconds=7776000, hash_ttl_seconds=15552000)
```

---

## Ejemplo mínimo: FastMCP Client (Python)

```python
from fastmcp import Client

# Conectar al servidor por proceso (stdio)
client = Client.from_stdio(["python", "-m", "mcp_win_admin.server"])  # o ruta a server.py

# Listar tools
tools = client.list_tools()
print([t.name for t in tools])

# Ejecutar reputación de IP con TTLs por fuente
res = client.call_tool(
    name="rep_check_ip",
    arguments={
        "ip": "1.2.3.4",
        "ttl_seconds": 86400,
        "ttl_by_source_json": "{\"greynoise\":3600,\"abuseipdb\":7200}",
    },
)
print(res)
```

---

## Buenas prácticas de seguridad para agentes

- Siempre requerir `confirm=true` para acciones que cambian el sistema.
- Evitar actuar sobre PIDs protegidos o procesos del sistema salvo política `Aggressive` y consentimiento explícito.
- Aplicar límites (`limit`, TTLs) y timeouts razonables.
- Registrar decisiones por webhook cuando proceda.

---

## Solución de problemas

- Si Inspector no detecta el servidor: verifica la ruta a `mcp_win_admin/server.py` y Python disponible en PATH.
- En reputación sin respuestas: comprueba conectividad de red y API keys.
- En Windows, ciertas tools pueden requerir consola elevada (Administrador).
