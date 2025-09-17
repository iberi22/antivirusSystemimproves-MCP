---
description: Inicia el dashboard FastAPI con WebSocket y abre el navegador
---

1) (Una vez) Instalar dependencias del proyecto
```powershell
python -m pip install -U pip wheel
pip install -e .
```

// turbo
2) Ejecutar el servidor del dashboard y abrir el navegador
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/dashboard/start.ps1 -Port 8787 -SkipInstall
```
