import os
import time
from typing import Dict, Optional, Tuple
from datetime import datetime, timezone

import httpx

from . import db
from . import config as cfg

_LAST_CALL: Dict[str, float] = {}
_MIN_INTERVAL = float(os.getenv("REP_THROTTLE_MIN_INTERVAL", "1.0"))  # seconds per source


def _throttle(key: str) -> None:
    now = time.monotonic()
    last = _LAST_CALL.get(key, 0.0)
    delta = now - last
    if delta < _MIN_INTERVAL:
        time.sleep(_MIN_INTERVAL - delta)
    _LAST_CALL[key] = time.monotonic()


def _vt_client() -> Optional[httpx.Client]:
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return None
    return httpx.Client(timeout=15, headers={"x-apikey": api_key})


def _otx_client() -> Optional[httpx.Client]:
    key = os.getenv("OTX_API_KEY")
    if not key:
        return None
    return httpx.Client(timeout=15, headers={"X-OTX-API-KEY": key})


def _greynoise_client() -> Optional[httpx.Client]:
    key = os.getenv("GREYNOISE_API_KEY")
    if not key:
        return None
    # GreyNoise community uses header 'key'
    return httpx.Client(timeout=15, headers={"key": key, "Accept": "application/json"})


def _abuseipdb_client() -> Optional[httpx.Client]:
    key = os.getenv("ABUSEIPDB_API_KEY")
    if not key:
        return None
    return httpx.Client(timeout=15, headers={"Key": key, "Accept": "application/json"})


def _threatfox_lookup(query_type: str, value: str, *, client: Optional[httpx.Client] = None) -> Dict:
    _throttle("threatfox")
    url = "https://threatfox-api.abuse.ch/api/v1/"
    close_client = False
    if client is None:
        client = httpx.Client(timeout=15)
        close_client = True
    try:
        payload = {"query": "search_ioc", "search_term": value}
        resp = client.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()
        status = data.get("query_status")
        if status == "ok" and data.get("data"):
            return {"source": "threatfox", "verdict": "malicious", "count": len(data.get("data", []))}
        return {"source": "threatfox", "verdict": "unknown", "status": status}
    except Exception as e:
        return {"source": "threatfox", "error": str(e), "verdict": "unknown"}
    finally:
        if close_client:
            client.close()


def _otx_ip_lookup(ip: str, *, client: Optional[httpx.Client] = None) -> Dict:
    _throttle("otx")
    if client is None:
        client = _otx_client()
    if client is None:
        return {"source": "otx", "verdict": "unknown", "status": "no_api_key"}
    try:
        resp = client.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general")
        if resp.status_code == 404:
            return {"source": "otx", "verdict": "unknown", "status": 404}
        resp.raise_for_status()
        data = resp.json()
        pulses = data.get("pulse_info", {}).get("count", 0)
        verdict = "malicious" if pulses > 0 else "unknown"
        return {"source": "otx", "verdict": verdict, "pulses": pulses}
    except Exception as e:
        return {"source": "otx", "error": str(e), "verdict": "unknown"}


def _otx_domain_lookup(domain: str, *, client: Optional[httpx.Client] = None) -> Dict:
    _throttle("otx")
    if client is None:
        client = _otx_client()
    if client is None:
        return {"source": "otx", "verdict": "unknown", "status": "no_api_key"}
    try:
        resp = client.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general")
        if resp.status_code == 404:
            return {"source": "otx", "verdict": "unknown", "status": 404}
        resp.raise_for_status()
        data = resp.json()
        pulses = data.get("pulse_info", {}).get("count", 0)
        verdict = "malicious" if pulses > 0 else "unknown"
        return {"source": "otx", "verdict": verdict, "pulses": pulses}
    except Exception as e:
        return {"source": "otx", "error": str(e), "verdict": "unknown"}


def _greynoise_ip_lookup(ip: str, *, client: Optional[httpx.Client] = None) -> Dict:
    _throttle("greynoise")
    if client is None:
        client = _greynoise_client()
    if client is None:
        return {"source": "greynoise", "verdict": "unknown", "status": "no_api_key"}
    try:
        # Community quick endpoint v2
        resp = client.get(f"https://api.greynoise.io/v2/noise/quick/{ip}")
        if resp.status_code == 404:
            return {"source": "greynoise", "verdict": "unknown", "status": 404}
        resp.raise_for_status()
        data = resp.json()
        riot = bool(data.get("riot"))
        noise = bool(data.get("noise"))
        verdict = "clean" if riot else ("suspicious" if noise else "unknown")
        return {"source": "greynoise", "verdict": verdict, "riot": riot, "noise": noise}
    except Exception as e:
        return {"source": "greynoise", "error": str(e), "verdict": "unknown"}


def _abuseipdb_ip_lookup(ip: str, *, client: Optional[httpx.Client] = None) -> Dict:
    _throttle("abuseipdb")
    if client is None:
        client = _abuseipdb_client()
    if client is None:
        return {"source": "abuseipdb", "verdict": "unknown", "status": "no_api_key"}
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        resp = client.get(url)
        if resp.status_code == 404:
            return {"source": "abuseipdb", "verdict": "unknown", "status": 404}
        resp.raise_for_status()
        data = resp.json().get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))
        verdict = "malicious" if score >= 70 else ("suspicious" if score > 0 else "unknown")
        return {"source": "abuseipdb", "verdict": verdict, "score": score}
    except Exception as e:
        return {"source": "abuseipdb", "error": str(e), "verdict": "unknown"}


def _urlhaus_host_lookup(host: str, *, client: Optional[httpx.Client] = None) -> Dict:
    _throttle("urlhaus")
    url = "https://urlhaus-api.abuse.ch/v1/host/"
    close_client = False
    if client is None:
        client = httpx.Client(timeout=15)
        close_client = True
    try:
        resp = client.post(url, data={"host": host})
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") == "ok" and data.get("urls"):
            return {"source": "urlhaus", "verdict": "malicious", "count": len(data.get("urls", []))}
        return {"source": "urlhaus", "verdict": "unknown", "status": data.get("query_status")}
    except Exception as e:
        return {"source": "urlhaus", "error": str(e), "verdict": "unknown"}
    finally:
        if close_client:
            client.close()


def _vt_ip_lookup(ip: str, *, client: Optional[httpx.Client]) -> Optional[Dict]:
    _throttle("virustotal")
    if client is None:
        return None
    try:
        resp = client.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}")
        if resp.status_code == 404:
            return {"source": "virustotal", "verdict": "unknown", "status": 404}
        resp.raise_for_status()
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        reps = attrs.get("reputation", 0)  # can be negative/positive
        malicious_cats = attrs.get("last_analysis_stats", {}).get("malicious", 0)
        verdict = "malicious" if malicious_cats and malicious_cats > 0 else ("suspicious" if reps > 0 else "unknown")
        return {"source": "virustotal", "verdict": verdict, "reputation": reps}
    except Exception as e:
        return {"source": "virustotal", "error": str(e), "verdict": "unknown"}


def _vt_domain_lookup(domain: str, *, client: Optional[httpx.Client]) -> Optional[Dict]:
    _throttle("virustotal")
    if client is None:
        return None
    try:
        resp = client.get(f"https://www.virustotal.com/api/v3/domains/{domain}")
        if resp.status_code == 404:
            return {"source": "virustotal", "verdict": "unknown", "status": 404}
        resp.raise_for_status()
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        reps = attrs.get("reputation", 0)
        malicious_cats = attrs.get("last_analysis_stats", {}).get("malicious", 0)
        verdict = "malicious" if malicious_cats and malicious_cats > 0 else ("suspicious" if reps > 0 else "unknown")
        return {"source": "virustotal", "verdict": verdict, "reputation": reps}
    except Exception as e:
        return {"source": "virustotal", "error": str(e), "verdict": "unknown"}


ORDER = {"malicious": 3, "suspicious": 2, "clean": 1, "unknown": 0}


def check_ip(
    ip: str,
    *,
    use_cloud: bool = True,
    ttl_seconds: Optional[int] = None,
    sources: Tuple[str, ...] = ("threatfox", "urlhaus"),
    ttl_by_source: Optional[Dict[str, int]] = None,
) -> Dict:
    # If using the default free-only sources and FREE_ONLY_SOURCES is disabled, extend to include paid/keyed sources
    if sources == ("threatfox", "urlhaus") and not cfg.FREE_ONLY_SOURCES:
        sources = ("threatfox", "urlhaus", "virustotal", "otx", "greynoise", "abuseipdb")
    out: Dict = {"ip": ip, "verdict": "unknown", "sources": []}
    cached = db.get_ip_reputation(ip=ip, ttl_seconds=ttl_seconds)
    if cached:
        out["cache"] = cached
        out["verdict"] = cached.get("verdict", out["verdict"])  # initial suggestion

    # Consultar caché por fuente (si existe). Si hay ttl_by_source, no filtramos en DB y aplicamos TTL por fuente en memoria.
    if ttl_by_source:
        cached_src_rows = db.get_ip_reputation_sources(ip=ip, ttl_seconds=None) or []
        filtered_rows: Dict[str, Dict] = {}
        now_ts = datetime.now(timezone.utc).timestamp()
        for row in cached_src_rows:
            src = str(row.get("source", ""))
            # TTL específico por fuente o fallback al ttl_seconds global si está definido
            ttl = ttl_by_source.get(src) if src in ttl_by_source else ttl_seconds
            if ttl is None or ttl < 0:
                filtered_rows[src] = row
                continue
            try:
                dt = datetime.fromisoformat(row.get("last_seen", ""))
                ts = dt.timestamp()
            except Exception:
                ts = 0
            if ts >= (now_ts - int(ttl)):
                filtered_rows[src] = row
        cached_by_source = filtered_rows
    else:
        cached_src_rows = db.get_ip_reputation_sources(ip=ip, ttl_seconds=ttl_seconds) or []
        cached_by_source = {row.get("source", ""): row for row in cached_src_rows}

    to_fetch: list[str] = []
    for s in sources:
        row = cached_by_source.get(s)
        if row:
            out["sources"].append({"source": s, "verdict": row.get("verdict", "unknown"), "cached": True})
        else:
            to_fetch.append(s)

    if use_cloud and to_fetch:
        vt_client = _vt_client()
        otx_client = _otx_client()
        gn_client = _greynoise_client()
        abuse_client = _abuseipdb_client()
        for s in to_fetch:
            if s == "threatfox":
                r = _threatfox_lookup("ip", ip)
            elif s == "urlhaus":
                r = _urlhaus_host_lookup(ip)
            elif s == "virustotal":
                r = _vt_ip_lookup(ip, client=vt_client) or {"source": "virustotal", "verdict": "unknown"}
            elif s == "otx":
                r = _otx_ip_lookup(ip, client=otx_client)
            elif s == "greynoise":
                r = _greynoise_ip_lookup(ip, client=gn_client)
            elif s == "abuseipdb":
                r = _abuseipdb_ip_lookup(ip, client=abuse_client)
            else:
                continue
            r = {**r, "cached": False}
            out["sources"].append(r)
            v = r.get("verdict", "unknown")
            src_name = r.get("source", s)
            try:
                # Escribir caché agregado y por fuente
                db.upsert_ip_reputation(ip=ip, verdict=v, source=src_name, metadata=None)
                db.upsert_ip_reputation_source(ip=ip, source=src_name, verdict=v, metadata=None)
            except Exception:
                pass

    best = out.get("verdict", "unknown")
    for src in out.get("sources", []):
        cand = src.get("verdict", "unknown")
        if ORDER.get(cand, -1) > ORDER.get(best, -1):
            best = cand
    out["verdict"] = best
    return out


def check_domain(
    domain: str,
    *,
    use_cloud: bool = True,
    ttl_seconds: Optional[int] = None,
    sources: Tuple[str, ...] = ("threatfox", "urlhaus"),
    ttl_by_source: Optional[Dict[str, int]] = None,
) -> Dict:
    # If using the default free-only sources and FREE_ONLY_SOURCES is disabled, extend to include paid/keyed domain sources
    if sources == ("threatfox", "urlhaus") and not cfg.FREE_ONLY_SOURCES:
        # Only include sources that support domain lookups
        sources = ("threatfox", "urlhaus", "virustotal", "otx")
    out: Dict = {"domain": domain, "verdict": "unknown", "sources": []}
    cached = db.get_domain_reputation(domain=domain, ttl_seconds=ttl_seconds)
    if cached:
        out["cache"] = cached
        out["verdict"] = cached.get("verdict", out["verdict"])  # initial suggestion

    if ttl_by_source:
        cached_src_rows = db.get_domain_reputation_sources(domain=domain, ttl_seconds=None) or []
        filtered_rows: Dict[str, Dict] = {}
        now_ts = datetime.now(timezone.utc).timestamp()
        for row in cached_src_rows:
            src = str(row.get("source", ""))
            ttl = ttl_by_source.get(src) if src in ttl_by_source else ttl_seconds
            if ttl is None or ttl < 0:
                filtered_rows[src] = row
                continue
            try:
                dt = datetime.fromisoformat(row.get("last_seen", ""))
                ts = dt.timestamp()
            except Exception:
                ts = 0
            if ts >= (now_ts - int(ttl)):
                filtered_rows[src] = row
        cached_by_source = filtered_rows
    else:
        cached_src_rows = db.get_domain_reputation_sources(domain=domain, ttl_seconds=ttl_seconds) or []
        cached_by_source = {row.get("source", ""): row for row in cached_src_rows}

    to_fetch: list[str] = []
    for s in sources:
        row = cached_by_source.get(s)
        if row:
            out["sources"].append({"source": s, "verdict": row.get("verdict", "unknown"), "cached": True})
        else:
            to_fetch.append(s)

    if use_cloud and to_fetch:
        vt_client = _vt_client()
        otx_client = _otx_client()
        for s in to_fetch:
            if s == "threatfox":
                r = _threatfox_lookup("domain", domain)
            elif s == "urlhaus":
                r = _urlhaus_host_lookup(domain)
            elif s == "virustotal":
                r = _vt_domain_lookup(domain, client=vt_client) or {"source": "virustotal", "verdict": "unknown"}
            elif s == "otx":
                r = _otx_domain_lookup(domain, client=otx_client)
            else:
                continue
            r = {**r, "cached": False}
            out["sources"].append(r)
            v = r.get("verdict", "unknown")
            src_name = r.get("source", s)
            try:
                db.upsert_domain_reputation(domain=domain, verdict=v, source=src_name, metadata=None)
                db.upsert_domain_reputation_source(domain=domain, source=src_name, verdict=v, metadata=None)
            except Exception:
                pass

    best = out.get("verdict", "unknown")
    for src in out.get("sources", []):
        cand = src.get("verdict", "unknown")
        if ORDER.get(cand, -1) > ORDER.get(best, -1):
            best = cand
    out["verdict"] = best
    return out
