param(
  [int]$Port = 5500
)

$ErrorActionPreference = 'Stop'

# Verifica que el directorio del reporte exista
if (-not (Test-Path 'web/report')) {
  Write-Error "No existe web/report. Verifica el repo."
  exit 1
}

Write-Host "[SERVE] http://localhost:$Port"
# Requiere npx y 'serve'
powershell -NoProfile -Command ("npx -y serve -l {0} web/report" -f $Port)
