import asyncio
import sys
import time
from pathlib import Path
import shutil

REPO_ROOT = Path(__file__).resolve().parents[1]

# Estado simple de diagnóstico para UI (no persistente)
DIAG_STATUS = {
    "status": "idle",  # idle|running|done|error
    "step": "",
    "progress": None,   # 0-100 o None si indeterminado
    "started_at": None,
    "finished_at": None,
    "last_rc": None,
    "last_stdout": "",
    "last_stderr": "",
}


def _resolve_powershell_exe() -> str:
    """Find a usable PowerShell executable (Windows PowerShell or PowerShell 7).

    Tries in order: powershell, powershell.exe, pwsh, pwsh.exe
    """
    for name in ("powershell", "powershell.exe", "pwsh", "pwsh.exe"):
        exe = shutil.which(name)
        if exe:
            return exe
    raise FileNotFoundError(
        "PowerShell executable not found. Install Windows PowerShell or PowerShell 7 and ensure it is in PATH."
    )


async def _run_ps1(path: Path) -> tuple[int, str, str]:
    exe = _resolve_powershell_exe()
    cmd = [
        exe,
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(path),
    ]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(REPO_ROOT),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_b, stderr_b = await proc.communicate()
    stdout = (stdout_b or b"").decode(errors="ignore")
    stderr = (stderr_b or b"").decode(errors="ignore")
    # TODO: opcionalmente, parsear stdout para pasos/porcentaje
    return proc.returncode, stdout, stderr


async def run_diagnostics_async() -> bool:
    # Marcar estado como en ejecución
    DIAG_STATUS.update({
        "status": "running",
        "step": "Ejecutando diagnóstico",
        "progress": None,
        "started_at": time.time(),
        "finished_at": None,
    })
    ps1 = REPO_ROOT / "scripts" / "adk" / "run_diagnostics.ps1"
    try:
        rc, out, err = await _run_ps1(ps1)
        ok = (rc == 0)
    except Exception as ex:
        ok = False
        rc, out, err = (999, "", f"{ex}")
    # Finalizar estado
    DIAG_STATUS.update({
        "status": "done" if ok else "error",
        "step": "Completado" if ok else f"Falló (rc={rc})",
        "progress": 100 if ok else None,
        "finished_at": time.time(),
        "last_rc": rc,
        "last_stdout": out[-4000:],  # limitar tamaño
        "last_stderr": err[-4000:],
    })
    return ok


async def prepare_report_async() -> bool:
    ps1 = REPO_ROOT / "scripts" / "adk" / "prepare_report.ps1"
    try:
        if not ps1.exists():
            # Falta el script, devolver False de forma controlada
            DIAG_STATUS.update({
                "status": "error",
                "step": "prepare_report: script no encontrado",
                "last_rc": 127,
                "last_stdout": "",
                "last_stderr": f"No existe: {ps1}",
            })
            return False
        rc, _out, _err = await _run_ps1(ps1)
        if rc != 0:
            # No lanzar 500: registrar en estado de diagnóstico para visibilidad
            DIAG_STATUS.update({
                "status": "error",
                "step": f"prepare_report falló (rc={rc})",
                "last_rc": rc,
                "last_stdout": (_out or "")[-2000:],
                "last_stderr": (_err or "")[-2000:],
            })
        return rc == 0
    except Exception as ex:
        # Evitar 500 desde FastAPI
        DIAG_STATUS.update({
            "status": "error",
            "step": "prepare_report excepción",
            "last_rc": 999,
            "last_stdout": "",
            "last_stderr": str(ex),
        })
        return False


def get_diagnostics_status() -> dict:
    """Devuelve el estado actual del diagnóstico para la UI."""
    return dict(DIAG_STATUS)
