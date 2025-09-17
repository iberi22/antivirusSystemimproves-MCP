$ErrorActionPreference = 'Stop'

# Asegura carpeta destino y copia artifacts
New-Item -ItemType Directory -Force web/report/artifacts | Out-Null
if (-not (Test-Path artifacts)) {
  Write-Host "[WARN] No existe ./artifacts; ejecuta primero run_diagnostics.ps1"
  exit 0
}
Copy-Item -Force -Path artifacts/* -Destination web/report/artifacts/
Write-Host "[OK] Copia completa a web/report/artifacts"
