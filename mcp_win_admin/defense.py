from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List
import os
import shutil
import json
from datetime import datetime, timezone
import hashlib
import psutil
import subprocess

from . import db
from . import alerts as alertmod
from . import config as cfg


QUARANTINE_DIR = Path.home() / ".mcp_win_admin" / "quarantine"


@dataclass
class Action:
    kind: str
    description: str
    command: str

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


def ensure_quarantine_dir() -> str:
    q = QUARANTINE_DIR
    try:
        q.mkdir(parents=True, exist_ok=True)
        return str(q)
    except Exception:
        # No lanzar error duro en dry-run
        return str(q)


# ---------------------------- Policies & Helpers ----------------------------

@dataclass
class Policy:
    name: str
    allow_kill_system: bool = False
    protected_pids: List[int] = None  # type: ignore[assignment]
    max_quarantine_size_mb: int = 100
    require_confirm: bool = True

    def __post_init__(self) -> None:
        if self.protected_pids is None:
            self.protected_pids = []


def _load_policy(name: str) -> Policy:
    key = (name or "").strip().lower()
    if key in ("aggressive",):
        return Policy(name="Aggressive", allow_kill_system=True, protected_pids=[], max_quarantine_size_mb=1024, require_confirm=True)
    if key in ("balanced",):
        return Policy(name="Balanced", allow_kill_system=False, protected_pids=[], max_quarantine_size_mb=256, require_confirm=True)
    # default strict
    return Policy(name="Strict", allow_kill_system=False, protected_pids=[0, 4], max_quarantine_size_mb=100, require_confirm=True)


_CRITICAL_NAMES = {
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
}


def _is_system_process(p: psutil.Process) -> bool:
    try:
        if p.pid in (0, 4):
            return True
        name = (p.name() or "").lower()
        if name in _CRITICAL_NAMES:
            return True
        username = (p.username() or "").lower()
        if "system" in username:
            return True
    except Exception:
        return False
    return False


def _sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def quarantine_dryrun(path: str) -> Dict:
    """Devuelve una acción en dry-run para mover un archivo a cuarentena.

    No realiza cambios.
    """
    ensure_quarantine_dir()
    p = Path(path)
    safe_name = p.name.replace(" ", "_")
    dest = QUARANTINE_DIR / safe_name
    cmd = f'powershell -NoProfile -ExecutionPolicy Bypass -Command "Move-Item -LiteralPath \"{p}\" -Destination \"{dest}\" -Force"'
    act = Action(kind="quarantine_move", description=f"Mover a cuarentena: {p} -> {dest}", command=cmd)
    return {"path": str(p), "quarantine": str(dest), "action": act.to_dict()}


def quarantine_execute(path: str, *, confirm: bool = False, policy_name: str = "Strict") -> Dict:
    """Ejecuta mover un archivo a cuarentena con políticas de seguridad.

    - confirm: debe ser True para ejecutar.
    - policy_name: Strict|Balanced|Aggressive
    """
    policy = _load_policy(policy_name)
    if policy.require_confirm and not confirm:
        return {"ok": False, "error": "confirmation_required", "message": "Se requiere confirmación explícita para ejecutar"}  # pragma: no cover

    ensure_quarantine_dir()
    p = Path(path)
    if not p.exists() or not p.is_file():
        return {"ok": False, "error": "not_found", "path": str(p)}
    try:
        size_mb = p.stat().st_size / (1024 * 1024)
    except Exception:
        size_mb = 0
    if policy.max_quarantine_size_mb > 0 and size_mb > policy.max_quarantine_size_mb:
        return {"ok": False, "error": "file_too_large", "limit_mb": policy.max_quarantine_size_mb, "size_mb": round(size_mb, 2)}

    # Preparar destino con timestamp y hash para evitar colisiones
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    try:
        sha256 = _sha256_file(p)
    except Exception:
        sha256 = ""
    base = p.name.replace(" ", "_")
    dest_name = f"{ts}__{sha256[:12]}__{base}" if sha256 else f"{ts}__{base}"
    dest = QUARANTINE_DIR / dest_name

    try:
        shutil.move(str(p), str(dest))
        manifest = {
            "action": "quarantine_move",
            "source_path": str(p),
            "dest_path": str(dest),
            "sha256": sha256,
            "ts_utc": datetime.now(timezone.utc).isoformat(),
            "policy": policy.name,
        }
        with (QUARANTINE_DIR / f"{dest_name}.manifest.json").open("w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)
        try:
            db.log_event("INFO", f"Quarantine executed: {p} -> {dest}")
        except Exception:
            pass
        try:
            alertmod.notify_webhook_if_configured(
                event="quarantine_executed",
                level="INFO",
                data=manifest,
            )
        except Exception:
            pass
        return {"ok": True, "path": str(p), "quarantine": str(dest), "sha256": sha256, "policy": policy.name}
    except Exception as e:
        try:
            db.log_event("ERROR", f"Quarantine failed for {p}: {e}")
        except Exception:
            pass
        return {"ok": False, "error": str(e), "path": str(p)}


def kill_process_dryrun(pid: int) -> Dict:
    """Devuelve la acción para terminar un proceso (dry-run)."""
    cmd = f"taskkill /PID {int(pid)} /F"
    act = Action(kind="kill_process", description=f"Terminar proceso PID={pid}", command=cmd)
    return {"pid": int(pid), "action": act.to_dict()}


def kill_process_execute(pid: int, *, confirm: bool = False, policy_name: str = "Strict") -> Dict:
    """Termina un proceso cumpliendo políticas (graceful -> force)."""
    policy = _load_policy(policy_name)
    if policy.require_confirm and not confirm:
        return {"ok": False, "error": "confirmation_required", "message": "Se requiere confirmación explícita para ejecutar"}
    try:
        p = psutil.Process(int(pid))
    except Exception as e:
        return {"ok": False, "error": str(e), "pid": int(pid)}

    if int(pid) in (policy.protected_pids or []):
        return {"ok": False, "error": "protected_pid", "pid": int(pid)}
    if not policy.allow_kill_system and _is_system_process(p):
        return {"ok": False, "error": "system_process", "pid": int(pid)}

    try:
        p.terminate()
        try:
            p.wait(timeout=3)
            db.log_event("INFO", f"Terminate process PID={pid} (policy={policy.name})")
            try:
                alertmod.notify_webhook_if_configured(
                    event="process_terminated",
                    level="INFO",
                    data={"pid": int(pid), "action": "terminated", "policy": policy.name},
                )
            except Exception:
                pass
            return {"ok": True, "pid": int(pid), "action": "terminated", "policy": policy.name}
        except Exception:
            p.kill()
            db.log_event("WARN", f"Killed process PID={pid} (policy={policy.name})")
            try:
                alertmod.notify_webhook_if_configured(
                    event="process_killed",
                    level="WARN",
                    data={"pid": int(pid), "action": "killed", "policy": policy.name},
                )
            except Exception:
                pass
            return {"ok": True, "pid": int(pid), "action": "killed", "policy": policy.name}
    except psutil.AccessDenied as e:
        db.log_event("ERROR", f"AccessDenied killing PID={pid}: {e}")
        return {"ok": False, "error": "access_denied", "pid": int(pid)}
    except Exception as e:
        db.log_event("ERROR", f"Error killing PID={pid}: {e}")
        return {"ok": False, "error": str(e), "pid": int(pid)}


def quarantine_bulk_dryrun(paths: List[str]) -> List[Dict]:
    out: List[Dict] = []
    for p in paths:
        try:
            out.append(quarantine_dryrun(p))
        except Exception as e:
            out.append({"path": p, "error": str(e)})
    return out


# ---------------------------- Process Isolation / Sandbox ----------------------------

def process_isolate_dryrun(pid: int) -> Dict:
    """Devuelve acciones (dry-run) para aislar un proceso mediante:

    - Bloqueo de tráfico IN/OUT por programa (netsh advfirewall)
    - Bajada de prioridad y afinidad CPU conservadora
    """
    cmd_fw_block_in = f'netsh advfirewall firewall add rule name="MCP Isolate PID={int(pid)} IN" dir=in action=block program="<exe_path>" enable=yes'
    cmd_fw_block_out = f'netsh advfirewall firewall add rule name="MCP Isolate PID={int(pid)} OUT" dir=out action=block program="<exe_path>" enable=yes'
    actions = [
        Action(kind="firewall_block_in", description="Bloquear IN por programa", command=cmd_fw_block_in).to_dict(),
        Action(kind="firewall_block_out", description="Bloquear OUT por programa", command=cmd_fw_block_out).to_dict(),
        Action(kind="lower_priority", description="Bajar prioridad y limitar afinidad", command=f"adjust_priority_affinity pid={int(pid)}").to_dict(),
    ]
    return {"pid": int(pid), "actions": actions}


def process_isolate_execute(pid: int, *, confirm: bool = False, policy_name: str = "Strict") -> Dict:
    """Aísla un proceso (sandbox ligero) controlado por políticas.

    Cambios realizados si confirm=True:
    - Crea reglas de firewall IN/OUT para bloquear el programa del proceso.
    - Baja prioridad y limita afinidad CPU (best-effort).
    """
    policy = _load_policy(policy_name)
    if policy.require_confirm and not confirm:
        return {"ok": False, "error": "confirmation_required", "message": "Se requiere confirmación explícita para ejecutar"}
    try:
        p = psutil.Process(int(pid))
    except Exception as e:
        return {"ok": False, "error": str(e), "pid": int(pid)}

    if int(pid) in (policy.protected_pids or []):
        return {"ok": False, "error": "protected_pid", "pid": int(pid)}
    if not policy.allow_kill_system and _is_system_process(p):
        return {"ok": False, "error": "system_process", "pid": int(pid)}

    exe_path = None
    try:
        exe_path = p.exe()
    except Exception:
        pass
    if not exe_path:
        return {"ok": False, "error": "exe_not_found", "pid": int(pid)}

    results: Dict[str, Dict] = {}
    # Firewall IN
    try:
        cmd_in = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name=MCP Isolate PID={int(pid)} IN", "dir=in", "action=block", f"program={exe_path}", "enable=yes",
        ]
        cp = subprocess.run(cmd_in, capture_output=True, text=True, shell=False, timeout=cfg.FIREWALL_CMD_TIMEOUT)
        results["firewall_in"] = {"rc": cp.returncode, "stdout": cp.stdout.strip(), "stderr": cp.stderr.strip()}
    except Exception as e:
        results["firewall_in"] = {"error": str(e)}
    # Firewall OUT
    try:
        cmd_out = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name=MCP Isolate PID={int(pid)} OUT", "dir=out", "action=block", f"program={exe_path}", "enable=yes",
        ]
        cp = subprocess.run(cmd_out, capture_output=True, text=True, shell=False, timeout=cfg.FIREWALL_CMD_TIMEOUT)
        results["firewall_out"] = {"rc": cp.returncode, "stdout": cp.stdout.strip(), "stderr": cp.stderr.strip()}
    except Exception as e:
        results["firewall_out"] = {"error": str(e)}

    # Ajustes de prioridad/afinidad (best-effort)
    try:
        try:
            p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)  # type: ignore[attr-defined]
        except Exception:
            pass
        try:
            if hasattr(p, "cpu_affinity"):
                aff = p.cpu_affinity()  # type: ignore[attr-defined]
                if isinstance(aff, list) and len(aff) > 1:
                    p.cpu_affinity(aff[: max(1, len(aff)//2)])  # type: ignore[attr-defined]
        except Exception:
            pass
        results["priority_affinity"] = {"ok": True}
    except Exception as e:  # pragma: no cover
        results["priority_affinity"] = {"error": str(e)}  # pragma: no cover

    try:
        db.log_event("INFO", f"Process isolated PID={pid} policy={policy.name}")
    except Exception:
        pass
    try:
        alertmod.notify_webhook_if_configured(
            event="process_isolated",
            level="INFO",
            data={"pid": int(pid), "exe": exe_path, "policy": policy.name},
        )
    except Exception:
        pass

    return {"ok": True, "pid": int(pid), "exe": exe_path, "policy": policy.name, "results": results}


def process_unsandbox_execute(pid: int, *, confirm: bool = False) -> Dict:
    """Revierte aislamiento: elimina reglas de firewall por programa y no toca prioridad/afinidad.

    Requiere confirm=True.
    """
    if not confirm:
        return {"ok": False, "error": "confirmation_required"}
    try:
        p = psutil.Process(int(pid))
    except Exception as e:
        return {"ok": False, "error": str(e), "pid": int(pid)}
    try:
        exe_path = p.exe()
    except Exception as e:
        return {"ok": False, "error": f"exe_not_found: {e}", "pid": int(pid)}

    results: Dict[str, Dict] = {}
    # Delete rules by program
    for dir_ in ("in", "out"):
        try:
            cmd = [
                "netsh", "advfirewall", "firewall", "delete", "rule", f"program={exe_path}", f"dir={dir_}",
            ]
            cp = subprocess.run(cmd, capture_output=True, text=True, shell=False, timeout=cfg.FIREWALL_CMD_TIMEOUT)
            results[f"delete_{dir_}"] = {"rc": cp.returncode, "stdout": cp.stdout.strip(), "stderr": cp.stderr.strip()}
        except Exception as e:
            results[f"delete_{dir_}"] = {"error": str(e)}

    try:
        db.log_event("INFO", f"Process unsandbox PID={pid}")
    except Exception:
        pass
    try:
        alertmod.notify_webhook_if_configured(
            event="process_unsandboxed",
            level="INFO",
            data={"pid": int(pid), "exe": exe_path},
        )
    except Exception:
        pass

    return {"ok": True, "pid": int(pid), "exe": exe_path, "results": results}
