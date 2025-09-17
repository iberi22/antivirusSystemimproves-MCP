---
description: Diagnóstico MCP Windows Admin con Inspector CLI (auto-run)
---

// turbo-all

Prerequisitos
- Tener el servidor MCP Python disponible vía `.\.venv\Scripts\python -m mcp_win_admin.server`.
- Tener Node.js/npx instalado.

Notas
- Todos los pasos usan Inspector CLI contra el servidor MCP real (STDIO).
- Ajusta rutas si tu venv no está en `.venv`.

1) Listar tools MCP
```powershell
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/list
```

2) Snapshot de rendimiento (sin persistir)
```powershell
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name system_scan_performance --tool-arg persist=false
```

3) Procesos: Top memoria
```powershell
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name processes_list --tool-arg fast=true --tool-arg include_cpu=true --tool-arg limit=25 --tool-arg sort_by=memory
```

4) Procesos: Top CPU (rápido)
```powershell
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name processes_list --tool-arg fast=true --tool-arg include_cpu=true --tool-arg limit=25 --tool-arg sort_by=cpu
```

5) Procesos: Top CPU (preciso)
```powershell
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name processes_list --tool-arg fast=false --tool-arg include_cpu=true --tool-arg limit=15 --tool-arg sort_by=cpu
```

6) Conexiones enriquecidas + reputación (limit 50)
```powershell
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name connections_list_enriched --tool-arg include_process=true --tool-arg kind=inet --tool-arg limit=50 --tool-arg listening_only=false
```

7) Autoruns
```powershell
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name startup_list --tool-arg limit=200
```

8) Tareas programadas
```powershell
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name tasks_list --tool-arg limit=150
```

9) Servicios en ejecución
```powershell
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name services_list --tool-arg limit=200 --tool-arg status=running
```

10) Eventos del sistema (últimos 100)
```powershell
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name events_list --tool-arg channel=System --tool-arg limit=100
```

11) Eventos de aplicaciones (últimos 100)
```powershell
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name events_list --tool-arg channel=Application --tool-arg limit=100
```

12) AV scan en Descargas (sin nube)
```powershell
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name av_scan_path --tool-arg target=C:\\Users\\belal\\Downloads --tool-arg recursive=true --tool-arg limit=500 --tool-arg sources_csv=malwarebazaar,teamcymru --tool-arg ttl_seconds=-1 --tool-arg use_cloud=false
```

13) AV scan en Temp (sin nube)
```powershell
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name av_scan_path --tool-arg target=C:\\Users\\belal\\AppData\\Local\\Temp --tool-arg recursive=true --tool-arg limit=500 --tool-arg sources_csv=malwarebazaar,teamcymru --tool-arg ttl_seconds=-1 --tool-arg use_cloud=false
```

14) Chequeo rootkit: puertos sin dueño
```powershell
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name rootkit_check_port_owners --tool-arg limit=300
```

15) Chequeo rootkit: procesos ocultos (heurística)
```powershell
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name rootkit_detect_hidden_processes --tool-arg limit=5000
```

16) Smoke test SDK oficial (opcional)
```powershell
.\.venv\Scripts\python.exe scripts\mcp_smoketest_stdio.py
```

Sección opcional: análisis de disco (ajusta rutas)
- Top de carpetas pesadas en `Documents/oxide-pilot`:
```powershell
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name fs_top_dirs --tool-arg root=C:\\Users\\belal\\Documents\\oxide-pilot --tool-arg max_depth=5 --tool-arg top_n=50 --tool-arg min_size_mb=50 --tool-arg follow_symlinks=true
```

Comandos en bruto (para allowlist si lo prefieres)
```
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/list
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name system_scan_performance --tool-arg persist=false
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name processes_list --tool-arg fast=true --tool-arg include_cpu=true --tool-arg limit=25 --tool-arg sort_by=memory
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name processes_list --tool-arg fast=true --tool-arg include_cpu=true --tool-arg limit=25 --tool-arg sort_by=cpu
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name processes_list --tool-arg fast=false --tool-arg include_cpu=true --tool-arg limit=15 --tool-arg sort_by=cpu
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name connections_list_enriched --tool-arg include_process=true --tool-arg kind=inet --tool-arg limit=50 --tool-arg listening_only=false
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name startup_list --tool-arg limit=200
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name tasks_list --tool-arg limit=150
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name services_list --tool-arg limit=200 --tool-arg status=running
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name events_list --tool-arg channel=System --tool-arg limit=100
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name events_list --tool-arg channel=Application --tool-arg limit=100
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name av_scan_path --tool-arg target=C:\\Users\\belal\\Downloads --tool-arg recursive=true --tool-arg limit=500 --tool-arg sources_csv=malwarebazaar,teamcymru --tool-arg ttl_seconds=-1 --tool-arg use_cloud=false
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name av_scan_path --tool-arg target=C:\\Users\\belal\\AppData\\Local\\Temp --tool-arg recursive=true --tool-arg limit=500 --tool-arg sources_csv=malwarebazaar,teamcymru --tool-arg ttl_seconds=-1 --tool-arg use_cloud=false
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name rootkit_check_port_owners --tool-arg limit=300
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name rootkit_detect_hidden_processes --tool-arg limit=5000
.\.venv\Scripts\python.exe scripts\mcp_smoketest_stdio.py
```
