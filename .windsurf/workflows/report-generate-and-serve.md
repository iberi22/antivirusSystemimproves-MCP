---
description: Genera artifacts JSON y sirve el reporte HTML/JS
---

// turbo-all

1) Crear carpeta de artifacts
```powershell
powershell -NoProfile -Command "New-Item -ItemType Directory -Force artifacts | Out-Null"
```

2) Snapshot de rendimiento
```powershell
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name system_scan_performance --tool-arg persist=false > artifacts\system_scan.json
```

3) Procesos (memoria)
```powershell
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name processes_list --tool-arg fast=true --tool-arg include_cpu=true --tool-arg limit=25 --tool-arg sort_by=memory > artifacts\processes_memory.json
```

4) Procesos (cpu, preciso)
```powershell
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name processes_list --tool-arg fast=false --tool-arg include_cpu=true --tool-arg limit=25 --tool-arg sort_by=cpu > artifacts\processes_cpu.json
```

5) Conexiones
```powershell
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name connections_list_enriched --tool-arg include_process=true --tool-arg kind=inet --tool-arg limit=100 --tool-arg listening_only=false > artifacts\connections.json
```

6) Autoruns, Tareas, Servicios
```powershell
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name startup_list --tool-arg limit=200 > artifacts\autoruns.json
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name tasks_list --tool-arg limit=200 > artifacts\tasks.json
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name services_list --tool-arg limit=200 > artifacts\services.json
```

7) Eventos (System + Application)
```powershell
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name events_list --tool-arg channel=System --tool-arg limit=100 > artifacts\events_system.json
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name events_list --tool-arg channel=Application --tool-arg limit=100 > artifacts\events_application.json
```

8) AV scans (sin nube)
```powershell
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name av_scan_path --tool-arg target=C:\\Users\\belal\\Downloads --tool-arg recursive=true --tool-arg limit=500 --tool-arg sources_csv=malwarebazaar,teamcymru --tool-arg ttl_seconds=-1 --tool-arg use_cloud=false > artifacts\av_downloads.json
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name av_scan_path --tool-arg target=C:\\Users\\belal\\AppData\\Local\\Temp --tool-arg recursive=true --tool-arg limit=500 --tool-arg sources_csv=malwarebazaar,teamcymru --tool-arg ttl_seconds=-1 --tool-arg use_cloud=false > artifacts\av_temp.json
```

9) Rootkit checks
```powershell
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name rootkit_check_port_owners --tool-arg limit=300 > artifacts\rootkit_ports.json
npx -y @modelcontextprotocol/inspector --cli .\.venv\Scripts\python -m mcp_win_admin.server --method tools/call --tool-name rootkit_detect_hidden_processes --tool-arg limit=5000 > artifacts\rootkit_hidden.json
```

10) Copiar artifacts al directorio del reporte
```powershell
powershell -NoProfile -Command "New-Item -ItemType Directory -Force web/report/artifacts | Out-Null"
powershell -NoProfile -Command "Copy-Item -Force -Path artifacts/* -Destination web/report/artifacts/"
```

11) Servir el reporte web en http://localhost:5500
```powershell
npx -y serve -l 5500 web/report
```
