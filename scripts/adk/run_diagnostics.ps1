param(
  [string]$PythonPath = ".\.venv\Scripts\python",
  [int]$Limit = 100
)

$ErrorActionPreference = 'Stop'

function Invoke-Inspector {
  param(
    [Parameter(Mandatory=$true)][string]$ToolName,
    [hashtable]$Args = @{},
    [string]$OutFile
  )
  $base = @(' -y', '@modelcontextprotocol/inspector', '--cli', $PythonPath, '-m', 'mcp_win_admin.server', '--method', 'tools/call', '--tool-name', $ToolName)
  foreach ($k in $Args.Keys) {
    $base += @('--tool-arg', ("{0}={1}" -f $k, $Args[$k]))
  }
  $cmd = 'npx ' + ($base -join ' ')
  if ($OutFile) {
    $cmd += (" > {0}" -f $OutFile)
  }
  Write-Host "[RUN] $cmd"
  powershell -NoProfile -Command $cmd | Out-Null
}

# Preparar directorio de artifacts
New-Item -ItemType Directory -Force artifacts | Out-Null

# Rutas dinámicas de usuario
$Downloads = Join-Path $env:USERPROFILE 'Downloads'
$TempPath = $env:TEMP

# 1) Snapshot
Invoke-Inspector -ToolName 'system_scan_performance' -Args @{ persist = 'false' } -OutFile 'artifacts/system_scan.json'

# 2) Procesos memoria
Invoke-Inspector -ToolName 'processes_list' -Args @{ fast='true'; include_cpu='true'; limit='25'; sort_by='memory' } -OutFile 'artifacts/processes_memory.json'

# 3) Procesos CPU (preciso)
Invoke-Inspector -ToolName 'processes_list' -Args @{ fast='false'; include_cpu='true'; limit='25'; sort_by='cpu' } -OutFile 'artifacts/processes_cpu.json'

# 4) Conexiones enriquecidas
Invoke-Inspector -ToolName 'connections_list_enriched' -Args @{ include_process='true'; kind='inet'; limit='100'; listening_only='false' } -OutFile 'artifacts/connections.json'

# 5) Autoruns, tareas, servicios
Invoke-Inspector -ToolName 'startup_list' -Args @{ limit='200' } -OutFile 'artifacts/autoruns.json'
Invoke-Inspector -ToolName 'tasks_list' -Args @{ limit='200' } -OutFile 'artifacts/tasks.json'
Invoke-Inspector -ToolName 'services_list' -Args @{ limit='200' } -OutFile 'artifacts/services.json'

# 6) Eventos
Invoke-Inspector -ToolName 'events_list' -Args @{ channel='System'; limit='100' } -OutFile 'artifacts/events_system.json'
Invoke-Inspector -ToolName 'events_list' -Args @{ channel='Application'; limit='100' } -OutFile 'artifacts/events_application.json'

# 7) AV scans (sin nube)
Invoke-Inspector -ToolName 'av_scan_path' -Args @{ target=$Downloads; recursive='true'; limit='500'; sources_csv='malwarebazaar,teamcymru'; ttl_seconds='-1'; use_cloud='false' } -OutFile 'artifacts/av_downloads.json'
Invoke-Inspector -ToolName 'av_scan_path' -Args @{ target=$TempPath; recursive='true'; limit='500'; sources_csv='malwarebazaar,teamcymru'; ttl_seconds='-1'; use_cloud='false' } -OutFile 'artifacts/av_temp.json'

# 8) Rootkit checks
Invoke-Inspector -ToolName 'rootkit_check_port_owners' -Args @{ limit='300' } -OutFile 'artifacts/rootkit_ports.json'
Invoke-Inspector -ToolName 'rootkit_detect_hidden_processes' -Args @{ limit='5000' } -OutFile 'artifacts/rootkit_hidden.json'

Write-Host "[OK] Diagnóstico completado. Artifacts en ./artifacts"
