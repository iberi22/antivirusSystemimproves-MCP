param(
  [int]$Port = 8787,
  [switch]$SkipInstall
)

$ErrorActionPreference = 'Stop'

# Ensure venv
if (-not (Test-Path .\.venv)) {
  Write-Host "[SETUP] Creando entorno virtual .venv"
  python -m venv .\.venv
}

# Activate venv
$activate = ".\.venv\Scripts\Activate.ps1"
. $activate

if (-not $SkipInstall) {
  Write-Host "[SETUP] Instalando dependencias del proyecto (-e .)"
  pip install -U pip wheel
  pip install -e .
}

# Launch server
$Url = "http://localhost:$Port"
Write-Host "[RUN] uvicorn dashboard_api.main:app --port $Port --reload"
Start-Process powershell -ArgumentList "-NoProfile", "-Command", "Start-Process '$Url'" | Out-Null
python -m uvicorn dashboard_api.main:app --port $Port --reload
