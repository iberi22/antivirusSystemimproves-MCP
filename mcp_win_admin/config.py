import os
from typing import Optional


def _get_bool(env: str, default: bool) -> bool:
    v = os.getenv(env)
    if v is None:
        return default
    v = v.strip().lower()
    return v in ("1", "true", "yes", "on")


def _get_int(env: str, default: int) -> int:
    try:
        return int(os.getenv(env, str(default)).strip())
    except Exception:
        return default


def _get_float(env: str, default: float) -> float:
    try:
        return float(os.getenv(env, str(default)).strip())
    except Exception:
        return default


# Flags generales
LIGHT_MODE: bool = _get_bool("MCP_LIGHT_MODE", True)

# Presupuestos/limites por categoría
PROC_LIST_MAX: int = _get_int("MCP_PROC_LIST_MAX", 50)
CONN_LIST_MAX: int = _get_int("MCP_CONN_LIST_MAX", 200)
EVENTS_MAX: int = _get_int("MCP_EVENTS_MAX", 1000)

# Alertas
WEBHOOK_TIMEOUT: float = _get_float("MCP_WEBHOOK_TIMEOUT", 3.0)
ENABLE_ALERTS: bool = _get_bool("MCP_ENABLE_ALERTS", True)
FIREWALL_CMD_TIMEOUT: float = _get_float("MCP_FIREWALL_CMD_TIMEOUT", 5.0)

# Reputación (sugerencias para modo ligero)
DEFAULT_REP_TTL: int = _get_int("MCP_DEFAULT_REP_TTL", 86400)  # 1 día
# Fuentes gratuitas solamente por defecto (omite servicios que requieren API key)
FREE_ONLY_SOURCES: bool = _get_bool("MCP_FREE_ONLY_SOURCES", True)

# Mantenimiento de base de datos
DB_MAINT_ENABLED: bool = _get_bool("MCP_DB_MAINT_ENABLED", True)
DB_MAINT_ON_START: bool = _get_bool("MCP_DB_MAINT_ON_START", True)
DB_MAINT_INTERVAL_SECONDS: int = _get_int("MCP_DB_MAINT_INTERVAL_SECONDS", 21600)  # 6 horas
# Purga (desactivada por defecto; establecer a >=0 para habilitar)
DB_PURGE_REP_TTL_SECONDS: int = _get_int("MCP_DB_PURGE_REP_TTL_SECONDS", -1)  # e.g. 7776000 (90 días)
DB_PURGE_EVENTS_TTL_SECONDS: int = _get_int("MCP_DB_PURGE_EVENTS_TTL_SECONDS", -1)  # e.g. 2592000 (30 días)
DB_PURGE_HASH_TTL_SECONDS: int = _get_int("MCP_DB_PURGE_HASH_TTL_SECONDS", -1)  # e.g. 15552000 (180 días)


def clamp_limit(requested: Optional[int], category: str) -> int:
    """Limita la cantidad a un máximo razonable basado en categoría.
    Si requested es None o <1, usa el máximo.
    """
    if category == "processes":
        cap = PROC_LIST_MAX
    elif category == "connections":
        cap = CONN_LIST_MAX
    elif category == "events":
        cap = EVENTS_MAX
    else:
        cap = max(50, _get_int("MCP_GENERIC_MAX", 500))
    if not requested or requested < 1:
        return cap
    return min(requested, cap)


def effective_rep_ttl(ttl_seconds: Optional[int]) -> Optional[int]:
    """Si ttl_seconds es None o <0, en modo ligero retorna DEFAULT_REP_TTL, si no retorna ttl_seconds limpio."""
    if ttl_seconds is None or ttl_seconds < 0:
        return DEFAULT_REP_TTL if LIGHT_MODE else None
    return int(ttl_seconds)


def get_effective_sources(sources_csv: str, default_sources: tuple[str, ...], extended_sources: tuple[str, ...]) -> tuple[str, ...]:
    """
    Determina las fuentes efectivas a utilizar basándose en el `sources_csv` proporcionado,
    la configuración de `FREE_ONLY_SOURCES` y las fuentes predeterminadas/extendidas.
    """
    # Analiza el `sources_csv` proporcionado por el usuario.
    user_sources = tuple(s.strip() for s in sources_csv.split(",") if s.strip())

    # Si el usuario no proporcionó ninguna fuente, usa las predeterminadas.
    if not user_sources:
        return default_sources

    # Si el usuario especificó fuentes explícitamente, úsalas.
    # Pero si el usuario usó las fuentes predeterminadas Y `FREE_ONLY_SOURCES` está desactivado,
    # entonces extiende las fuentes para incluir las no gratuitas.
    if user_sources == default_sources and not FREE_ONLY_SOURCES:
        return extended_sources

    return user_sources
