import asyncio
import json
import os
import time
from typing import List, Dict, Tuple, Any, Callable

import psutil
import shutil
import subprocess
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi import APIRouter
from pydantic import BaseModel
try:
    import wmi  # type: ignore
except Exception:  # optional on some systems
    wmi = None

from . import metrics, actions
from mcp_win_admin import filesystem as fs_mod
from mcp_win_admin import connections as con_mod
from mcp_win_admin import defense as def_mod
from mcp_win_admin import profiles as prof_mod
from .mcp_client import mcp_singleton as mcp

app = FastAPI(title="Windows Admin Dashboard", version="0.1.0")

# Mount static assets (CSS/JS) from dashboard_ui/
app.mount("/static", StaticFiles(directory="dashboard_ui"), name="static")
router = APIRouter(prefix="/api")


@app.on_event("shutdown")
async def _shutdown_mcp():
    try:
        await mcp.stop()
    except Exception:
        pass


@router.get("/metrics")
async def get_metrics():
    return metrics.snapshot()


@router.get("/processes/top")
async def get_processes_top(by: str = "memory", limit: int = 10):
    return metrics.top_processes(by=by, limit=limit)


@router.get("/connections")
async def get_connections(limit: int = 50):
    return metrics.connections(limit=limit)


# --------------------------- MCP proxy endpoints ---------------------------
class ToolCallBody(BaseModel):
    args: Dict[str, Any] | None = None


@router.get("/mcp/health")
async def mcp_health():
    return await mcp.health()


@router.get("/mcp/tools")
async def mcp_tools():
    try:
        return await mcp.list_tools()
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


@router.post("/mcp/restart")
async def mcp_restart():
    """Reinicia la sesión MCP stdio (recarga binario Rust actualizado)."""
    try:
        await mcp.restart()
        return {"ok": True}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


@router.get("/mcp/sensors")
async def mcp_sensors():
    """Thin wrapper over MCP `sensors.get` if available."""
    try:
        return await mcp.call_tool_json("sensors.get", {})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


@router.post("/mcp/tool/{name}")
async def mcp_tool_call(name: str, body: ToolCallBody):
    try:
        args = body.args or {}
        return await mcp.call_tool_json(name, args)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


@router.get("/mcp/metrics")
async def mcp_metrics():
    """Thin wrapper over MCP `metrics.get` for easy UI consumption."""
    try:
        return await mcp.call_tool_json("metrics.get", {})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


@router.get("/mcp/processes")
async def mcp_processes(by: str = "memory_rss", limit: int = 50):
    """Thin wrapper over MCP `process.list` with optional sort and limit.

    - by: one of memory_rss | cpu_percent (best-effort)
    - limit: 1..200
    """
    try:
        limit = max(1, min(200, int(limit)))
        data = await mcp.call_tool_json("process.list", {})
        items = None
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            # Support { "processes": [...] }
            arr = data.get("processes")
            if isinstance(arr, list):
                items = arr
        if items is None:
            return data  # pass-through unknown shape

        # Best-effort sorting
        key = "memory_rss"
        if by.lower() in ("cpu", "cpu_percent"):
            key = "cpu_percent"
        elif by:
            key = by
        try:
            items = sorted(items, key=lambda p: (p or {}).get(key) or 0, reverse=True)
        except Exception:
            pass
        return items[:limit]
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


def _cpu_temp_wmi() -> float | None:
    """Best-effort CPU temperature via WMI (Windows)."""
    try:
        if not wmi:
            return None
        w = wmi.WMI(namespace="root\\WMI")
        sensors = w.MSAcpi_ThermalZoneTemperature()
        vals = []
        for s in sensors:
            # CurrentTemperature is in tenths of Kelvin
            k10 = getattr(s, "CurrentTemperature", None)
            if k10 is None:
                continue
            c = (k10 / 10.0) - 273.15
            if -50.0 < c < 150.0:
                vals.append(c)
        if vals:
            return round(sum(vals) / len(vals), 1)
    except Exception:
        pass
    return None


def _cpu_temp_psutil() -> float | None:
    try:
        temps = psutil.sensors_temperatures(fahrenheit=False)
        if not temps:
            return None
        # Try common keys
        for key in ("coretemp", "acpitz", "cpu-thermal", "k10temp"):
            arr = temps.get(key)
            if arr:
                vals = [t.current for t in arr if getattr(t, "current", None) is not None]
                if vals:
                    return round(sum(vals) / len(vals), 1)
    except Exception:
        pass
    return None


def _gpu_temp_nvidia() -> float | None:
    """Use nvidia-smi if available."""
    try:
        exe = shutil.which("nvidia-smi")
        if not exe:
            return None
        out = subprocess.check_output([exe, "--query-gpu=temperature.gpu", "--format=csv,noheader,nounits"], timeout=2)
        val = out.decode().strip().splitlines()[0].strip()
        if val:
            return float(val)
    except Exception:
        return None
    return None


def _temps_openhw_wmi() -> dict:
    """Best-effort temps via OpenHardwareMonitor/LibreHardwareMonitor WMI.

    Returns keys: cpu, gpu; values are floats or None.
    Requires the corresponding monitor app running with WMI provider enabled.
    """
    out = {"cpu": None, "gpu": None}
    if not wmi:
        return out
    namespaces = ["root\\OpenHardwareMonitor", "root\\LibreHardwareMonitor"]
    for ns in namespaces:
        try:
            w = wmi.WMI(namespace=ns)  # type: ignore[attr-defined]
            # Some providers expose a Sensor class with Temperature readings
            rows = w.Sensor(SensorType="Temperature")  # type: ignore[attr-defined]
            cpu_vals = []
            gpu_vals = []
            for r in rows:
                try:
                    name = str(getattr(r, "Name", "") or "")
                    hw = str(getattr(r, "Hardware", "") or "")
                    val = getattr(r, "Value", None)
                    if val is None:
                        continue
                    # Heuristics: group by hardware/name
                    s = name.lower() + " " + hw.lower()
                    if ("cpu" in s) or ("core" in s and "gpu" not in s):
                        cpu_vals.append(float(val))
                    if "gpu" in s:
                        gpu_vals.append(float(val))
                except Exception:
                    continue
            if cpu_vals and out["cpu"] is None:
                out["cpu"] = round(sum(cpu_vals) / len(cpu_vals), 1)
            if gpu_vals and out["gpu"] is None:
                out["gpu"] = round(sum(gpu_vals) / len(gpu_vals), 1)
            if out["cpu"] is not None or out["gpu"] is not None:
                break
        except Exception:
            continue
    return out


def _net_info() -> dict:
    stats = psutil.net_if_stats()
    io = psutil.net_io_counters(pernic=True)
    out = []
    for name, st in stats.items():
        d = {
            "name": name,
            "isup": getattr(st, "isup", False),
            "speed_mbps": getattr(st, "speed", 0) or None,
            "mtu": getattr(st, "mtu", None),
            "duplex": getattr(st, "duplex", None),
            "bytes_sent": (io.get(name).bytes_sent if io.get(name) else None),
            "bytes_recv": (io.get(name).bytes_recv if io.get(name) else None),
        }
        out.append(d)
    # Pick a primary: highest speed and up
    primary = None
    ups = [x for x in out if x["isup"]]
    if ups:
        primary = sorted(ups, key=lambda x: (x["speed_mbps"] or 0), reverse=True)[0]["name"]
    return {"primary": primary, "interfaces": out}


@router.get("/sensors")
async def sensors():
    # Try vendor/monitor WMI first (more reliable on Windows), then fallbacks.
    ohm = _temps_openhw_wmi()
    cpu = ohm.get("cpu") or _cpu_temp_psutil() or _cpu_temp_wmi()
    gpu = ohm.get("gpu") or _gpu_temp_nvidia()
    # RAM/Disco temperaturas son poco fiables en Windows sin herramientas de fabricante
    ram = None
    disk = None
    net = _net_info()
    return {
        "cpu_temp_c": cpu,
        "gpu_temp_c": gpu,
        "ram_temp_c": ram,
        "disk_temp_c": disk,
        "net": net,
    }


def _list_heavy_files(root: str, max_depth: int = 2, top_n: int = 3, follow_symlinks: bool = False) -> List[Dict]:
    """Top-N archivos más pesados bajo `root` hasta `max_depth` (simple y tolerante a errores)."""
    root = os.path.abspath(root)
    results: List[Tuple[int, str]] = []  # (size, path)
    try:
        start_depth = root.rstrip(os.sep).count(os.sep)
        for cur, dirs, files in os.walk(root, followlinks=follow_symlinks):
            try:
                depth = cur.rstrip(os.sep).count(os.sep) - start_depth
                if depth > max_depth:
                    # No descender más
                    dirs[:] = []
                    continue
                for fn in files:
                    fp = os.path.join(cur, fn)
                    try:
                        sz = os.path.getsize(fp)
                        results.append((sz, fp))
                    except Exception:
                        continue
            except Exception:
                continue
    except Exception:
        pass
    results.sort(key=lambda t: t[0], reverse=True)
    out = [{"path": p, "size_bytes": s, "size_mb": round(s / (1024*1024), 2)} for s, p in results[: max(1, top_n)]]
    return out


@router.get("/fs/heavy")
async def fs_heavy(limit: int = 3, max_depth: int = 2, min_size_mb: int = 200):
    """Devuelve para cada disco: uso, top-N carpetas pesadas (con hijos) y top-N archivos pesados."""
    try:
        data = []
        try:
            parts = psutil.disk_partitions(all=False)
        except Exception:
            parts = []
        for part in parts:
            root = part.mountpoint
            opts = (getattr(part, "opts", "") or "").lower()
            # Skip CD-ROM and non-directories/unmounted roots
            if "cdrom" in opts:
                continue
            if not os.path.isdir(root):
                continue
            try:
                usage = psutil.disk_usage(root)
            except Exception:
                continue
            try:
                dirs = fs_mod.list_heavy_paths(
                    root=root,
                    max_depth=max_depth,
                    top_n=limit,
                    min_size_mb=min_size_mb,
                    follow_symlinks=False,
                )
            except Exception:
                dirs = []
            # Añadir hijos y top_files de forma tolerante a errores
            for d in dirs:
                try:
                    d["children"] = fs_mod.list_heavy_paths(
                        root=d["path"], max_depth=1, top_n=limit, min_size_mb=max(10, min_size_mb // 10), follow_symlinks=False
                    )
                except Exception:
                    d["children"] = []
                try:
                    d["top_files"] = _list_heavy_files(root=d["path"], max_depth=1, top_n=5)
                except Exception:
                    d["top_files"] = []
            try:
                files = _list_heavy_files(root=root, max_depth=max_depth, top_n=limit)
            except Exception:
                files = []
            data.append({
                "device": part.device,
                "mountpoint": root,
                "percent": usage.percent,
                "dirs": dirs,
                "files": files,
            })
        return data
    except Exception:
        # Never 500; return empty on unexpected conditions
        return []


@router.get("/fs/tree")
async def fs_tree(drive: str = "C", top_n: int = 3, max_depth: int = 2, min_size_mb: int = 200):
    root = f"{drive}:\\" if len(drive) == 1 and not drive.endswith(":\\") else drive
    try:
        dirs = fs_mod.list_heavy_paths(
            root=root, max_depth=max_depth, top_n=top_n, min_size_mb=min_size_mb, follow_symlinks=False
        )
        for d in dirs:
            try:
                d["children"] = fs_mod.list_heavy_paths(
                    root=d["path"], max_depth=1, top_n=top_n, min_size_mb=max(10, min_size_mb // 10), follow_symlinks=False
                )
            except Exception:
                d["children"] = []
        return {"drive": root, "top_dirs": dirs, "top_files": _list_heavy_files(root, max_depth=max_depth, top_n=top_n)}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


@router.get("/network/hosts")
async def network_hosts():
    """Agrega conexiones por host remoto y por proceso para vista resumida de red."""
    conns = con_mod.list_connections(limit=500, kind="inet", listening_only=False, include_process=True)
    host_map: Dict[str, Dict] = {}
    proc_map: Dict[str, Dict] = {}
    for c in conns:
        raddr = c.get("raddr")
        if not raddr:
            continue
        h = host_map.setdefault(raddr, {"host": raddr, "count": 0, "pids": set(), "processes": set(), "states": set()})
        h["count"] += 1
        if c.get("pid"):
            h["pids"].add(c.get("pid"))
        if c.get("process_name"):
            h["processes"].add(c.get("process_name"))
        if c.get("status"):
            h["states"].add(c.get("status"))

        pname = c.get("process_name") or f"pid:{c.get('pid')}"
        p = proc_map.setdefault(pname, {"process": pname, "pid": c.get("pid"), "hosts": set(), "states": set()})
        p["hosts"].add(raddr)
        if c.get("status"):
            p["states"].add(c.get("status"))

    hosts = [
        {
            "host": h["host"],
            "count": h["count"],
            "pids": sorted(list(h["pids"])),
            "processes": sorted(list(h["processes"])),
            "states": sorted(list(h["states"]))
        }
        for h in host_map.values()
    ]
    processes = [
        {
            "process": p["process"],
            "pid": p["pid"],
            "hosts": sorted(list(p["hosts"])),
            "states": sorted(list(p["states"]))
        }
        for p in proc_map.values()
    ]
    hosts.sort(key=lambda x: x["count"], reverse=True)
    processes.sort(key=lambda x: len(x["hosts"]), reverse=True)
    return {"hosts": hosts[:100], "processes": processes[:100]}


@router.get("/action/diagnostics/status")
async def action_diagnostics_status():
    return actions.get_diagnostics_status()


@router.post("/action/diagnostics")
async def action_diagnostics():
    asyncio.create_task(actions.run_diagnostics_async())
    return JSONResponse({"status": "accepted", "action": "diagnostics"}, status_code=202)


@router.post("/action/report/prepare")
async def action_report_prepare():
    ok = await actions.prepare_report_async()
    return {"status": "ok" if ok else "error"}


# --------------------------- Info Aggregator ---------------------------

_cache_sections: Dict[str, Tuple[float, Any]] = {}
_SECTION_TTLS: Dict[str, float] = {
    "core": 2.0,
    "diagnostics": 2.0,
    "sensors": 3.0,
    "disks": 5.0,
}


async def _info_fetch_core():
    # Prefer Rust MCP metrics.get when available; fallback to local snapshot
    try:
        res = await asyncio.wait_for(mcp.call_tool_json("metrics.get", {}), timeout=1.5)
        if isinstance(res, dict) and res:
            return res
    except Exception:
        pass
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, metrics.snapshot)


async def _info_fetch_diagnostics():
    # Lectura local rápida (no bloqueante)
    return actions.get_diagnostics_status()


async def _info_fetch_sensors():
    # Reutiliza el handler de /api/sensors
    return await sensors()


async def _info_fetch_disks():
    # Extrae solo la parte de discos desde snapshot para payload liviano
    loop = asyncio.get_running_loop()
    snap = await loop.run_in_executor(None, metrics.snapshot)
    return snap.get("disks") or []


async def _get_section_cached(name: str, fetcher: Callable[[], Any], ttl: float):
    now = time.time()
    cached = _cache_sections.get(name)
    if cached and (now - cached[0]) <= ttl:
        return cached[1]
    val = await fetcher()
    _cache_sections[name] = (now, val)
    return val


@router.get("/info")
async def info(sections: str = "core,diagnostics"):
    req = [s.strip().lower() for s in sections.split(',') if s.strip()]
    req_set = set(req)
    out: Dict[str, Any] = {}
    errors: Dict[str, str] = {}
    tasks = []
    names: List[str] = []
    core_requested = "core" in req_set
    disks_requested = "disks" in req_set
    for s in req:
        if s == "core":
            tasks.append(_get_section_cached("core", _info_fetch_core, _SECTION_TTLS["core"]))
            names.append("core")
        elif s == "diagnostics":
            tasks.append(_get_section_cached("diagnostics", _info_fetch_diagnostics, _SECTION_TTLS["diagnostics"]))
            names.append("diagnostics")
        elif s == "sensors":
            tasks.append(_get_section_cached("sensors", _info_fetch_sensors, _SECTION_TTLS["sensors"]))
            names.append("sensors")
        elif s == "disks":
            # Si también se solicitó 'core', derivamos discos desde ese resultado para evitar doble snapshot
            if not core_requested:
                tasks.append(_get_section_cached("disks", _info_fetch_disks, _SECTION_TTLS["disks"]))
                names.append("disks")
            # else: no agendar, se derivará tras el gather
        else:
            # ignorar secciones desconocidas
            continue
    if tasks:
        res = await asyncio.gather(*tasks, return_exceptions=True)
        for name, val in zip(names, res):
            if isinstance(val, Exception):
                errors[name] = str(val)
            else:
                out[name] = val
    # Derivar 'disks' desde 'core' cuando ambos fueron requeridos
    if disks_requested and core_requested:
        if "core" in out:
            try:
                out["disks"] = (out["core"].get("disks") or [])
            except Exception as e:
                errors["disks"] = f"unavailable (failed to derive from core: {e})"
        else:
            # Si 'core' falló, reflejar dependencia en el error de 'disks'
            core_err = errors.get("core", "core missing")
            errors["disks"] = f"unavailable (core failed: {core_err})"
    return {"sections": out, "partial": bool(errors), "errors": errors or None, "ts": int(time.time())}


# --------------------------- GameBooster / Defense API ---------------------------

class KillReq(BaseModel):
    pid: int
    policy_name: str = "Strict"
    confirm: bool = True


class IsolateReq(BaseModel):
    pid: int
    policy_name: str = "Strict"
    confirm: bool = True


class UnsandboxReq(BaseModel):
    pid: int
    confirm: bool = True


class QuarantineReq(BaseModel):
    path: str
    policy_name: str = "Strict"
    confirm: bool = True


@router.get("/profiles")
async def profiles_list():
    try:
        return {"profiles": prof_mod.list_profiles()}
    except Exception as e:  # pragma: no cover
        return JSONResponse({"error": str(e)}, status_code=400)


@router.get("/profiles/preview")
async def profiles_preview(name: str):
    try:
        return prof_mod.preview_profile(name)
    except Exception as e:  # pragma: no cover
        return JSONResponse({"error": str(e)}, status_code=400)


@router.get("/gamebooster/candidates")
async def gamebooster_candidates(limit: int = 10):
    """Heurística simple de candidatos a cerrar/aislar durante juego.

    No ejecuta cambios. Solo sugiere candidatos con metadatos y razones.
    """
    limit = max(1, min(50, int(limit)))
    items = metrics.top_processes(by="memory", limit=50)
    patterns = (
        "onedrive", "teams", "slack", "discord", "updater", "update", "helper",
        "launcher", "electron", "telemetry", "agent", "assistant", "cloud",
    )
    out = []
    for p in items:
        try:
            pid = int(p.get("pid"))
            proc = psutil.Process(pid)
            if def_mod._is_system_process(proc):  # best-effort
                continue
            name = (p.get("name") or "").lower()
            if any(tok in name for tok in patterns):
                out.append({
                    "pid": pid,
                    "name": p.get("name"),
                    "memory_rss": p.get("memory_rss"),
                    "cpu_percent": p.get("cpu_percent"),
                    "safe_to_kill": False,  # Requiere verificación/consentimiento
                    "reason": "Coincide con patrón de fondo",
                })
        except Exception:
            continue
        if len(out) >= limit:
            break
    return {"candidates": out}


@router.post("/process/kill")
async def process_kill(req: KillReq):
    try:
        res = def_mod.kill_process_execute(pid=req.pid, confirm=req.confirm, policy_name=req.policy_name)
        return res
    except Exception as e:  # pragma: no cover
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


@router.post("/process/isolate")
async def process_isolate(req: IsolateReq):
    try:
        res = def_mod.process_isolate_execute(pid=req.pid, confirm=req.confirm, policy_name=req.policy_name)
        return res
    except Exception as e:  # pragma: no cover
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


@router.post("/process/unsandbox")
async def process_unsandbox(req: UnsandboxReq):
    try:
        res = def_mod.process_unsandbox_execute(pid=req.pid, confirm=req.confirm)
        return res
    except Exception as e:  # pragma: no cover
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


@router.post("/file/quarantine")
async def file_quarantine(req: QuarantineReq):
    try:
        res = def_mod.quarantine_execute(path=req.path, confirm=req.confirm, policy_name=req.policy_name)
        return res
    except Exception as e:  # pragma: no cover
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


app.include_router(router)


@app.get("/")
async def index():
    return FileResponse("dashboard_ui/index.html")

@app.get("/gamebooster")
async def gamebooster():
    return FileResponse("dashboard_ui/gamebooster.html")

@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = metrics.snapshot()
            await websocket.send_text(json.dumps(data))
            await asyncio.sleep(2.0)
    except WebSocketDisconnect:
        return

# Alias para permitir "/ws/" y evitar errores 400 por barra final
@app.websocket("/ws/")
async def ws_endpoint_alias(websocket: WebSocket):
    await ws_endpoint(websocket)
