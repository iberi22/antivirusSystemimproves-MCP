import json
import threading
import time

from mcp.server.fastmcp import FastMCP

from . import db
from . import processes as procmod
from . import profiles as profmod
from . import system as sysmod
from . import av as avmod
from . import services as svcmod
from . import connections as conmod
from . import events as evtmod
from . import startup as stmod
from . import tasks as tmod
from . import integrity as intmod
from . import reputation as repmod
from . import yara_scan as yaramod
from . import drivers as drvmod
from . import rootkit as rkmod
from . import firewall as fwmod
from . import updates as upmod
from . import monitor_usn as usnmod
from . import defense as defmod
from . import alerts as alertmod
from . import filesystem as fsmod
from . import config as cfg

# Inicializa la base de datos (WAL) al cargar el servidor
try:
    db.init_db()
except Exception as e:
    # Evitar que el servidor caiga por fallo de inicialización de DB
    try:
        db.log_event("ERROR", f"Fallo init_db: {e}")
    except Exception:
        pass

# Hilo de mantenimiento de base de datos (PRAGMA optimize + purgas)
def _start_db_maintenance_thread() -> None:
    if not cfg.DB_MAINT_ENABLED:
        return

    def _loop() -> None:
        # Ejecución opcional al iniciar
        if cfg.DB_MAINT_ON_START:
            try:
                db.optimize_db()
            except Exception:
                try:
                    db.log_event("WARN", "optimize_db on start failed")
                except Exception:
                    pass
            try:
                db.purge_old_data(
                    events_ttl_seconds=cfg.DB_PURGE_EVENTS_TTL_SECONDS,
                    reputation_ttl_seconds=cfg.DB_PURGE_REP_TTL_SECONDS,
                    hash_ttl_seconds=cfg.DB_PURGE_HASH_TTL_SECONDS,
                )
            except Exception:
                try:
                    db.log_event("WARN", "purge_old_data on start failed")
                except Exception:
                    pass

        interval = max(300, int(getattr(cfg, "DB_MAINT_INTERVAL_SECONDS", 21600)))
        while True:
            try:
                time.sleep(interval)
                db.optimize_db()
                db.purge_old_data(
                    events_ttl_seconds=cfg.DB_PURGE_EVENTS_TTL_SECONDS,
                    reputation_ttl_seconds=cfg.DB_PURGE_REP_TTL_SECONDS,
                    hash_ttl_seconds=cfg.DB_PURGE_HASH_TTL_SECONDS,
                )
            except Exception as e:
                try:
                    db.log_event("WARN", f"DB maintenance loop error: {e}")
                except Exception:
                    pass

    th = threading.Thread(target=_loop, name="DBMaint", daemon=True)
    th.start()

_start_db_maintenance_thread()

# Crea el servidor MCP
mcp = FastMCP("MCP Windows Admin")


@mcp.tool()
def system_scan_performance(persist: bool = True) -> dict:
    """Escanea el rendimiento del sistema y (opcional) persiste el snapshot en SQLite.

    - persist: True para guardar snapshot (WAL) y devolver id.
    """
    snap = sysmod.get_performance_snapshot()
    row_id: int | None = None
    if persist:
        try:
            row_id = db.insert_snapshot(snap.to_dict())
        except Exception as e:
            db.log_event("WARN", f"No se pudo guardar snapshot: {e}")
    return {"snapshot": snap.to_dict(), "persisted_id": row_id}


@mcp.tool()
def processes_list(
    limit: int = 20,
    sort_by: str = "memory",
    fast: bool = True,
    include_cpu: bool = False,
) -> list[dict]:
    """Lista procesos con métricas básicas.

    - sort_by: memory|cpu|pid
    - fast: True evita cálculos costosos (username/CPU) salvo que se pidan
    - include_cpu: True calcula cpu_percent (puede añadir latencia)
    """
    lim = cfg.clamp_limit(limit, "processes")
    return procmod.list_processes(limit=lim, sort_by=sort_by, fast=fast, include_cpu=include_cpu)


@mcp.tool()
def profiles_list() -> list[dict]:
    """Lista perfiles disponibles y número de acciones sugeridas."""
    return profmod.list_profiles()


@mcp.tool()
def profiles_preview(name: str) -> dict:
    """Muestra las acciones sugeridas por un perfil (sin ejecutar cambios)."""
    return profmod.preview_profile(name)


@mcp.resource("snapshot://last")
def last_snapshot() -> str:
    """Recurso con el último snapshot persistido en formato JSON (texto)."""
    data = db.get_last_snapshot() or {"message": "No hay snapshots almacenados"}
    return json.dumps(data, ensure_ascii=False)


@mcp.tool()
def db_optimize() -> dict:
    """Ejecuta mantenimiento ligero de SQLite (PRAGMA optimize + WAL checkpoint PASSIVE)."""
    try:
        return db.optimize_db()
    except Exception as e:
        return {"ok": False, "error": str(e)}


@mcp.tool()
def db_purge_old(events_ttl_seconds: int = -1, reputation_ttl_seconds: int = -1, hash_ttl_seconds: int = -1) -> dict:
    """Purgar datos antiguos (events/reputation/hashes) según TTLs. Valores <0 desactivan la purga.

    - events_ttl_seconds: TTL para eventos (`events.ts_utc`).
    - reputation_ttl_seconds: TTL para reputación (`last_seen`).
    - hash_ttl_seconds: TTL para veredictos de hash (`last_seen`).
    """
    try:
        return db.purge_old_data(
            events_ttl_seconds=events_ttl_seconds,
            reputation_ttl_seconds=reputation_ttl_seconds,
            hash_ttl_seconds=hash_ttl_seconds,
        )
    except Exception as e:
        return {"ok": False, "error": str(e)}


def main() -> None:
    mcp.run()


# ---------------------------- Antivirus Tools ----------------------------

@mcp.tool()
def av_check_hash(hash_hex: str, algo: str = "sha256", use_cloud: bool = True, ttl_seconds: int = -1, sources_csv: str = "malwarebazaar,teamcymru") -> dict:
    """Verifica un hash contra caché local y (opcional) fuentes en la nube (p.ej. VirusTotal).

    Requiere variable de entorno VT_API_KEY para consultas en la nube.
    """
    sources = tuple(s.strip() for s in sources_csv.split(",") if s.strip()) or ("virustotal",)
    # Si el usuario no personalizó fuentes (usa el default) y FREE_ONLY_SOURCES está desactivado, ampliamos para incluir VT
    if sources_csv == "malwarebazaar,teamcymru" and not cfg.FREE_ONLY_SOURCES:
        sources = ("virustotal", "malwarebazaar", "teamcymru")
    ttl = cfg.effective_rep_ttl(ttl_seconds)
    return avmod.check_hash(hash_hex, algo=algo, use_cloud=use_cloud, sources=sources, ttl_seconds=ttl)


@mcp.tool()
def av_scan_path(target: str, recursive: bool = True, limit: int = 1000, algo: str = "sha256", use_cloud: bool = False, ttl_seconds: int = -1, sources_csv: str = "malwarebazaar,teamcymru") -> list[dict]:
    """Escanea archivos bajo un path (archivo o carpeta) y contrasta hashes. No desinfecta."""
    ttl = cfg.effective_rep_ttl(ttl_seconds)
    sources = tuple(s.strip() for s in sources_csv.split(",") if s.strip()) or ("malwarebazaar", "teamcymru")
    if sources_csv == "malwarebazaar,teamcymru" and not cfg.FREE_ONLY_SOURCES:
        sources = ("virustotal", "malwarebazaar", "teamcymru")
    return avmod.scan_path(target, recursive=recursive, limit=limit, algo=algo, use_cloud=use_cloud, sources=sources, ttl_seconds=ttl)


# ---------------------------- Windows Services ----------------------------

@mcp.tool()
def services_list(status: str = "", limit: int = 200) -> list[dict]:
    """Lista servicios de Windows con estado y binario."""
    lim = cfg.clamp_limit(limit, "processes")
    return svcmod.list_services(status=status, limit=lim)


# ---------------------------- Network Connections ----------------------------

@mcp.tool()
def connections_list(limit: int = 100, kind: str = "inet", listening_only: bool = False, include_process: bool = False) -> list[dict]:
    """Lista conexiones de red (TCP/UDP)."""
    lim = cfg.clamp_limit(limit, "connections")
    return conmod.list_connections(limit=lim, kind=kind, listening_only=listening_only, include_process=include_process)


# ---------------------------- Windows Event Log ----------------------------

@mcp.tool()
def events_list(channel: str = "System", limit: int = 100) -> list[dict]:
    """Lista eventos recientes del Windows Event Log (puede requerir privilegios)."""
    return evtmod.list_events(channel=channel, limit=limit)


# ---------------------------- Autoruns & Scheduled Tasks ----------------------------

@mcp.tool()
def startup_list(limit: int = 200) -> list[dict]:
    """Lista elementos de inicio (autoruns) desde registro y carpetas Startup."""
    return stmod.list_startup(limit=limit)


@mcp.tool()
def fs_top_dirs(
    root: str = "C:\\",
    max_depth: int = 2,
    top_n: int = 30,
    min_size_mb: int = 200,
    follow_symlinks: bool = False,
) -> list[dict]:
    """Lista directorios más pesados bajo `root` hasta `max_depth`.

    - root: raíz a analizar (e.g., C:\\)
    - max_depth: profundidad máxima de análisis (2-3 recomendado)
    - top_n: cantidad de directorios a devolver
    - min_size_mb: umbral mínimo en MB
    - follow_symlinks: seguir o no enlaces simbólicos
    """
    return fsmod.list_heavy_paths(
        root=root,
        max_depth=max_depth,
        top_n=top_n,
        min_size_mb=min_size_mb,
        follow_symlinks=follow_symlinks,
    )


@mcp.tool()
def tasks_list(limit: int = 200, state: str = "") -> list[dict]:
    """Lista tareas programadas (schtasks)."""
    return tmod.list_scheduled_tasks(limit=limit, state=state)


# ---------------------------- File Integrity ----------------------------

@mcp.tool()
def integrity_build_baseline(name: str, root_path: str, algo: str = "sha256", recursive: bool = True, limit: int = 10000) -> dict:
    """Construye/actualiza un baseline de integridad para un directorio."""
    return intmod.build_baseline(name=name, root_path=root_path, algo=algo, recursive=recursive, limit=limit)


@mcp.tool()
def integrity_verify_baseline(name: str, recursive: bool = True, limit: int = 10000, algo: str = "") -> dict:
    """Verifica cambios (añadidos, modificados, removidos) respecto al baseline."""
    algo_opt = algo or None
    res = intmod.verify_baseline(name=name, recursive=recursive, limit=limit, algo=algo_opt)
    # Alerta reactiva si hay cambios (best-effort, no afecta retorno)
    try:
        summary = res.get("summary") or {}
        if any(int(summary.get(k, 0)) > 0 for k in ("added", "removed", "modified")):
            try:
                db.log_event("WARN", f"Integrity changes detected in baseline='{name}': {summary}")
            except Exception:
                pass
            try:
                alertmod.notify_webhook_if_configured(
                    event="integrity_change_detected",
                    level="WARN",
                    data={"baseline": name, "summary": summary},
                )
            except Exception:
                pass
    except Exception:
        pass
    # Asegura eco de parámetros esperados por clientes/tests
    try:
        res.setdefault("name", name)
        res.setdefault("recursive", recursive)
        res.setdefault("limit", limit)
        if algo == "":
            # Mantiene cadena vacía si fue solicitada explícitamente
            res["algo"] = ""
    except Exception:
        pass
    return res


@mcp.tool()
def integrity_list_baselines() -> list[dict]:
    """Lista baselines de integridad guardados."""
    return intmod.list_baselines()


@mcp.tool()
def integrity_diff_baselines(name_a: str, name_b: str) -> dict:
    """Compara dos baselines guardados y devuelve diferencias (no accede al FS)."""
    return intmod.diff_baselines(name_a, name_b)


# ---------------------------- Reputation Tools ----------------------------

@mcp.tool()
def rep_check_ip(ip: str, use_cloud: bool = True, ttl_seconds: int = -1, sources_csv: str = "threatfox,urlhaus", ttl_by_source_json: str = "") -> dict:
    """Consulta reputación de IP (ThreatFox/URLHaus/VT si disponible) con caché local y TTL."""
    sources = tuple(s.strip() for s in sources_csv.split(",") if s.strip()) or ("threatfox",)
    if sources_csv == "threatfox,urlhaus" and not cfg.FREE_ONLY_SOURCES:
        sources = ("threatfox", "urlhaus", "virustotal", "otx", "greynoise", "abuseipdb")
    ttl = cfg.effective_rep_ttl(ttl_seconds)
    ttl_by_source = None
    if ttl_by_source_json:
        try:
            ttl_by_source = json.loads(ttl_by_source_json)
        except Exception:
            ttl_by_source = None
    return repmod.check_ip(ip, use_cloud=use_cloud, ttl_seconds=ttl, sources=sources, ttl_by_source=ttl_by_source)


@mcp.tool()
def rep_check_domain(domain: str, use_cloud: bool = True, ttl_seconds: int = -1, sources_csv: str = "threatfox,urlhaus", ttl_by_source_json: str = "") -> dict:
    """Consulta reputación de dominio (ThreatFox/URLHaus/VT si disponible) con caché local y TTL."""
    sources = tuple(s.strip() for s in sources_csv.split(",") if s.strip()) or ("threatfox",)
    if sources_csv == "threatfox,urlhaus" and not cfg.FREE_ONLY_SOURCES:
        sources = ("threatfox", "urlhaus", "virustotal", "otx")
    ttl = cfg.effective_rep_ttl(ttl_seconds)
    ttl_by_source = None
    if ttl_by_source_json:
        try:
            ttl_by_source = json.loads(ttl_by_source_json)
        except Exception:
            ttl_by_source = None
    return repmod.check_domain(domain, use_cloud=use_cloud, ttl_seconds=ttl, sources=sources, ttl_by_source=ttl_by_source)


@mcp.tool()
def connections_list_enriched(limit: int = 100, kind: str = "inet", listening_only: bool = False, include_process: bool = False, rep_ttl_seconds: int = 86400, rep_sources_csv: str = "threatfox,urlhaus", rep_ttl_by_source_json: str = "") -> list[dict]:
    """Lista conexiones y añade reputación del host remoto (si aplica)."""
    lim = cfg.clamp_limit(limit, "connections")
    items = conmod.list_connections(limit=lim, kind=kind, listening_only=listening_only, include_process=include_process)
    # Construir set de IPs remotas
    ips: dict[str, dict] = {}
    sources = tuple(s.strip() for s in rep_sources_csv.split(",") if s.strip()) or ("threatfox",)
    if rep_sources_csv == "threatfox,urlhaus" and not cfg.FREE_ONLY_SOURCES:
        sources = ("threatfox", "urlhaus", "virustotal", "otx", "greynoise", "abuseipdb")
    ttl = cfg.effective_rep_ttl(rep_ttl_seconds)
    ttl_by_source = None
    if rep_ttl_by_source_json:
        try:
            ttl_by_source = json.loads(rep_ttl_by_source_json)
        except Exception:
            ttl_by_source = None
    for it in items:
        raddr = it.get("raddr")
        if not raddr:
            continue
        ip = raddr.split(":")[0]
        if ip and ip not in ips:
            try:
                ips[ip] = repmod.check_ip(ip, use_cloud=True, ttl_seconds=ttl, sources=sources, ttl_by_source=ttl_by_source)
            except Exception:
                ips[ip] = {"ip": ip, "verdict": "unknown"}
    # Anotar
    for it in items:
        raddr = it.get("raddr")
        if not raddr:
            continue
        ip = raddr.split(":")[0]
        if ip in ips:
            it["reputation"] = ips[ip]
    return items


# ---------------------------- YARA Tools ----------------------------

@mcp.tool()
def yara_scan_path(target: str, rules_path: str = "", rule_text: str = "", recursive: bool = True, limit: int = 1000) -> dict:
    """Escanea un path con YARA. Requiere 'yara-python'.

    - rules_path: archivo o directorio con reglas (.yar/.yara)
    - rule_text: texto de una regla YARA (alternativo a rules_path)
    """
    rp = rules_path or None
    rt = rule_text or None
    return yaramod.scan_path(target, rules_path=rp, rule_text=rt, recursive=recursive, limit=limit)


@mcp.tool()
def yara_test_rule(rule_text: str, sample_path: str) -> dict:
    """Prueba una regla YARA contra un archivo de muestra."""
    return yaramod.test_rule(rule_text, sample_path)


# ---------------------------- Drivers ----------------------------

@mcp.tool()
def drivers_list(limit: int = 500) -> list[dict]:
    """Lista drivers del sistema (WMI)."""
    return drvmod.list_drivers(limit=limit)


# ---------------------------- Rootkit heuristics ----------------------------

@mcp.tool()
def rootkit_detect_hidden_processes(limit: int = 10000) -> dict:
    """Compara procesos WMI vs psutil para detectar discrepancias (heurística)."""
    return rkmod.detect_hidden_processes(limit=limit)


@mcp.tool()
def rootkit_check_port_owners(limit: int = 1000) -> list[dict]:
    """Lista conexiones sin PID asociado (posibles anomalías)."""
    return rkmod.check_port_owners(limit=limit)


# ---------------------------- Firewall ----------------------------

@mcp.tool()
def firewall_list_rules(limit: int = 500) -> list[dict]:
    """Lista reglas del firewall de Windows (netsh)."""
    return fwmod.list_rules(limit=limit)


@mcp.tool()
def firewall_export_rules(file_path: str) -> dict:
    """Exporta reglas del firewall a un archivo."""
    return fwmod.export_rules(file_path)


@mcp.tool()
def firewall_block_ip_dryrun(ip: str) -> dict:
    """Devuelve el comando netsh para bloquear una IP (solo dry-run)."""
    return fwmod.block_ip_dryrun(ip)


# ---------------------------- Windows Updates ----------------------------

@mcp.tool()
def updates_list_installed(limit: int = 200) -> list[dict]:
    """Lista hotfixes/actualizaciones instaladas (WMI)."""
    return upmod.list_installed(limit=limit)


@mcp.tool()
def updates_trigger_scan_dryrun() -> dict:
    """Devuelve el comando para iniciar un escaneo de Windows Update (dry-run)."""
    return upmod.trigger_scan_dryrun()


# ---------------------------- Telemetry / Events ----------------------------

@mcp.tool()
def telemetry_list_events(limit: int = 1000) -> list[dict]:
    """Lista entradas de eventos/telemetría almacenadas en SQLite."""
    return db.list_events(limit=limit)


# ---------------------------- Defense (Dry-Run) ----------------------------

@mcp.tool()
def defense_quarantine_dryrun(path: str) -> dict:
    """Devuelve la acción (dry-run) para mover un archivo a cuarentena."""
    return defmod.quarantine_dryrun(path)


@mcp.tool()
def defense_kill_process_dryrun(pid: int) -> dict:
    """Devuelve la acción (dry-run) para terminar un proceso por PID."""
    return defmod.kill_process_dryrun(pid)


@mcp.tool()
def defense_quarantine_bulk_dryrun(paths_csv: str) -> list[dict]:
    """Devuelve acciones (dry-run) para cuarentenar múltiples rutas separadas por coma."""
    paths = [p.strip() for p in paths_csv.split(",") if p.strip()]
    return defmod.quarantine_bulk_dryrun(paths)


# ---------------------------- Defense (Execute) ----------------------------

@mcp.tool()
def defense_quarantine_execute(path: str, confirm: bool = False, policy_name: str = "Strict") -> dict:
    """Ejecuta mover un archivo a cuarentena (controlado por política)."""
    return defmod.quarantine_execute(path, confirm=confirm, policy_name=policy_name)


@mcp.tool()
def defense_kill_process_execute(pid: int, confirm: bool = False, policy_name: str = "Strict") -> dict:
    """Termina un proceso (controlado por política)."""
    return defmod.kill_process_execute(pid, confirm=confirm, policy_name=policy_name)


# ---------------------------- Defense (Isolation) ----------------------------

@mcp.tool()
def defense_process_isolate_dryrun(pid: int) -> dict:
    """Devuelve acciones (dry-run) para aislar un proceso (firewall + prioridad/afinidad)."""
    return defmod.process_isolate_dryrun(pid)


@mcp.tool()
def defense_process_isolate_execute(pid: int, confirm: bool = False, policy_name: str = "Strict") -> dict:
    """Aísla un proceso (reglas firewall + ajustes de prioridad/afinidad), controlado por políticas."""
    return defmod.process_isolate_execute(pid, confirm=confirm, policy_name=policy_name)


@mcp.tool()
def defense_process_unsandbox_execute(pid: int, confirm: bool = False) -> dict:
    """Revierte aislamiento eliminando reglas de firewall asociadas al ejecutable del proceso."""
    return defmod.process_unsandbox_execute(pid, confirm=confirm)


# ---------------------------- Alerts / Notifications ----------------------------

@mcp.tool()
def alert_notify_webhook(event: str, level: str = "INFO", data_json: str = "{}", url: str = "") -> dict:
    """Envía un evento a un webhook. Si 'url' está vacío, usa env ALERT_WEBHOOK_URL."""
    try:
        data = json.loads(data_json) if data_json else {}
    except Exception:
        data = {}
    if url.strip():
        return alertmod.notify_webhook(url.strip(), event, level, data)
    alertmod.notify_webhook_if_configured(event, level, data)
    return {"ok": True, "used_env": True}


@mcp.tool()
def alert_notify_toast(title: str, message: str) -> dict:
    """Muestra una notificación tipo toast en Windows (best-effort)."""
    return alertmod.notify_toast(title, message)


# ---------------------------- USN Journal ----------------------------

@mcp.tool()
def usn_query_info(drive: str = "C") -> dict:
    """Consulta información del USN Journal para una unidad (solo lectura)."""
    return usnmod.query_usn_info(drive)


if __name__ == "__main__":
    main()
