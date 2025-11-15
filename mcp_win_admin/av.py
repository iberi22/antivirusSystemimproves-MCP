import hashlib
import os
import socket
import os as _os
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import httpx
import time

from . import db
from . import config as cfg
from . import scanner
from . import behavioral


SUPPORTED_ALGOS = ("sha256", "md5", "sha1")

_LAST_CALL: Dict[str, float] = {}
_MIN_INTERVAL = 0.5  # seconds per source


def _throttle(key: str) -> None:
    now = time.monotonic()
    last = _LAST_CALL.get(key, 0.0)
    delta = now - last
    if delta < _MIN_INTERVAL:
        time.sleep(_MIN_INTERVAL - delta)
    _LAST_CALL[key] = time.monotonic()


def _hash_file(path: Path, algo: str = "sha256", chunk_size: int = 1024 * 1024) -> str:
    algo_l = algo.lower()
    if algo_l not in SUPPORTED_ALGOS:
        raise ValueError(f"Unsupported algo: {algo}")
    h = hashlib.new(algo_l)
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def hash_files(paths: Iterable[Path], algos: Tuple[str, ...] = ("sha256",)) -> List[Dict]:
    results: List[Dict] = []
    for p in paths:
        try:
            item = {"path": str(p.resolve())}
            for a in algos:
                item[a] = _hash_file(p, a)
            results.append(item)
        except Exception as e:
            results.append({"path": str(p), "error": str(e)})
    return results


def _walk_files(base: Path, recursive: bool = True, limit: Optional[int] = None) -> Iterable[Path]:
    count = 0
    if base.is_file():
        yield base
        return
    if recursive:
        for root, _, files in os.walk(base):
            for name in files:
                p = Path(root) / name
                yield p
                count += 1
                if limit and count >= limit:
                    return
    else:
        for p in base.iterdir():
            if p.is_file():
                yield p
                count += 1
                if limit and count >= limit:
                    return


def vt_lookup_hash(hash_hex: str, *, client: Optional[httpx.Client] = None) -> Optional[Dict]:
    _throttle("virustotal")
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return None
    url = f"https://www.virustotal.com/api/v3/files/{hash_hex}"
    close_client = False
    if client is None:
        client = httpx.Client(timeout=15)
        close_client = True
    try:
        resp = client.get(url, headers={"x-apikey": api_key})
        if resp.status_code == 404:
            return {"source": "virustotal", "verdict": "unknown", "status": 404}
        resp.raise_for_status()
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        if malicious > 0:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"
        elif harmless > 0 and malicious == 0 and suspicious == 0:
            verdict = "clean"
        else:
            verdict = "unknown"
        return {
            "source": "virustotal",
            "verdict": verdict,
            "stats": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
            },
            "permalink": f"https://www.virustotal.com/gui/file/{hash_hex}",
        }
    except Exception as e:
        return {"source": "virustotal", "error": str(e), "verdict": "unknown"}
    finally:
        if close_client:
            client.close()


def teamcymru_mhr_lookup_hash(hash_hex: str) -> Optional[Dict]:
    """Consulta Team Cymru MHR vía DNS A query.

    - MD5/SHA1: un solo label.
    - SHA256: dividir en dos segmentos de 32 caracteres.
    Devuelve 'malicious' si responde 127.0.0.2, 'unknown' si NXDOMAIN u otro error.
    """
    try:
        h = hash_hex.lower()
        if len(h) == 64:  # sha256
            name = f"{h[:32]}.{h[32:]}.hash.cymru.com"
        else:
            name = f"{h}.hash.cymru.com"
        timeout_s = float(_os.getenv("MHR_DNS_TIMEOUT", "2.0"))
        ip = None
        use_dns_lib = _os.getenv("MHR_USE_DNSPYTHON", "1").strip().lower() not in {"0", "false", "no"}
        # Intentar con dnspython si está disponible (timeouts configurables)
        if use_dns_lib:
            try:
                import dns.resolver  # type: ignore

                resolver = dns.resolver.Resolver()  # type: ignore[attr-defined]
                resolver.timeout = timeout_s  # type: ignore[attr-defined]
                resolver.lifetime = timeout_s  # type: ignore[attr-defined]
                ans = resolver.resolve(name, "A")  # type: ignore[attr-defined]
                for r in ans:
                    ip = r.address  # type: ignore[attr-defined]
                    break
            except Exception:
                pass
        if ip is None:
            # Fallback a socket.gethostbyname (sin control fino de timeout)
            try:
                ip = socket.gethostbyname(name)
            except Exception:
                return {"source": "teamcymru", "verdict": "unknown"}
        if ip == "127.0.0.2":
            return {"source": "teamcymru", "verdict": "malicious"}
        return {"source": "teamcymru", "verdict": "unknown", "ip": ip}
    except Exception as e:
        return {"source": "teamcymru", "error": str(e), "verdict": "unknown"}


def check_hash(
    hash_hex: str,
    *,
    algo: str = "sha256",
    use_cloud: bool = True,
    sources: Tuple[str, ...] = ("malwarebazaar", "teamcymru"),
    ttl_seconds: Optional[int] = None,
) -> Dict:
    """Check a hash against cache and optionally cloud sources.

    Returns: dict with consolidated verdict and per-source details.
    """
    algo = algo.lower()
    out: Dict = {"hash": hash_hex, "algo": algo, "verdict": "unknown", "sources": []}

    # If using the default free-only sources and FREE_ONLY_SOURCES is disabled, extend to include VirusTotal
    if sources == ("malwarebazaar", "teamcymru") and not cfg.FREE_ONLY_SOURCES:
        sources = ("virustotal", "malwarebazaar", "teamcymru")

    cached = db.get_hash_verdict(hash_hex=hash_hex, algo=algo, ttl_seconds=ttl_seconds)
    if cached:
        out["cache"] = cached
        out["verdict"] = cached.get("verdict", out["verdict"])  # initial suggestion

    if use_cloud:
        for s in sources:
            if s == "virustotal":
                vt = vt_lookup_hash(hash_hex)
                if vt is not None:
                    out["sources"].append(vt)
                    v = vt.get("verdict", "unknown")
                    # persist best effort
                    try:
                        db.upsert_hash_verdict(
                            hash_hex=hash_hex,
                            algo=algo,
                            verdict=v,
                            source="virustotal",
                            metadata=None,
                        )
                    except Exception:
                        pass
            elif s == "malwarebazaar":
                mb = malwarebazaar_lookup_hash(hash_hex)
                if mb is not None:
                    out["sources"].append(mb)
                    v = mb.get("verdict", "unknown")
                    try:
                        db.upsert_hash_verdict(
                            hash_hex=hash_hex,
                            algo=algo,
                            verdict=v,
                            source="malwarebazaar",
                            metadata=None,
                        )
                    except Exception:
                        pass
            elif s == "teamcymru":
                tc = teamcymru_mhr_lookup_hash(hash_hex)
                if tc is not None:
                    out["sources"].append(tc)
                    v = tc.get("verdict", "unknown")
                    try:
                        db.upsert_hash_verdict(
                            hash_hex=hash_hex,
                            algo=algo,
                            verdict=v,
                            source="teamcymru",
                            metadata=None,
                        )
                    except Exception:
                        pass
    # consolidate: prefer worst verdict among sources
    order = {"malicious": 3, "suspicious": 2, "clean": 1, "unknown": 0}
    best = out.get("verdict", "unknown")
    for src in out.get("sources", []):
        cand = src.get("verdict", "unknown")
        if order.get(cand, -1) > order.get(best, -1):
            best = cand
    out["verdict"] = best
    return out


def scan_path(
    target: str,
    *,
    recursive: bool = True,
    limit: Optional[int] = 1000,
    algo: str = "sha256",
    use_cloud: bool = False,
    sources: Tuple[str, ...] = ("malwarebazaar", "teamcymru"),
    ttl_seconds: Optional[int] = None,
) -> List[Dict]:
    """Scan a path (file or directory) computing hashes and checking verdicts.

    limit caps the number of files to avoid extremely long scans.
    """
    base = Path(target).expanduser()
    # If using the default free-only sources and FREE_ONLY_SOURCES is disabled, extend to include VirusTotal
    if sources == ("malwarebazaar", "teamcymru") and not cfg.FREE_ONLY_SOURCES:
        sources = ("virustotal", "malwarebazaar", "teamcymru")
    files = list(_walk_files(base, recursive=recursive, limit=limit))
    results: List[Dict] = []
    for f in files:
        try:
            h = _hash_file(f, algo)
            verdict = check_hash(h, algo=algo, use_cloud=use_cloud, sources=sources, ttl_seconds=ttl_seconds)
            results.append({
                "path": str(f),
                "algo": algo,
                "hash": h,
                "verdict": verdict.get("verdict", "unknown"),
                "details": verdict,
            })
        except Exception as e:
            results.append({"path": str(f), "error": str(e)})
    return results


def malwarebazaar_lookup_hash(hash_hex: str, *, client: Optional[httpx.Client] = None) -> Optional[Dict]:
    _throttle("malwarebazaar")
    """Consulta MalwareBazaar (abuse.ch) por hash (sha256 preferido).

    Devuelve dict con 'verdict': 'malicious' si hay coincidencia, 'unknown' si no.
    """
    url = "https://mb-api.abuse.ch/api/v1/"
    close_client = False
    if client is None:
        client = httpx.Client(timeout=15)
        close_client = True
    try:
        resp = client.post(url, data={"query": "get_info", "hash": hash_hex})
        if resp.status_code == 404:
            return {"source": "malwarebazaar", "verdict": "unknown", "status": 404}
        resp.raise_for_status()
        data = resp.json()
        status = data.get("query_status")
        if status == "ok" and data.get("data"):
            return {"source": "malwarebazaar", "verdict": "malicious", "count": len(data.get("data", []))}
        return {"source": "malwarebazaar", "verdict": "unknown", "status": status}
    except Exception as e:
        return {"source": "malwarebazaar", "error": str(e), "verdict": "unknown"}
    finally:
        if close_client:
            client.close()

def scan_path_modern(
    target: str,
    *,
    limit: Optional[int] = 1000,
    algo: str = "sha256",
    use_cloud: bool = False,
    sources: Tuple[str, ...] = ("malwarebazaar", "teamcymru"),
    ttl_seconds: Optional[int] = None,
    use_behavioral_scan: bool = False,
) -> List[Dict]:
    """Scan a path (file or directory) computing hashes and checking verdicts.

    limit caps the number of files to avoid extremely long scans.
    """
    results: List[Dict] = []

    if use_behavioral_scan:
        results.extend(behavioral.check_running_processes())

    try:
        path_hashes = scanner.scan_path_parallel(target)
        if limit:
            path_hashes = path_hashes[:limit]

        for path, h, _, _ in path_hashes:
            try:
                verdict = check_hash(h, algo=algo, use_cloud=use_cloud, sources=sources, ttl_seconds=ttl_seconds)
                results.append({
                    "path": path,
                    "algo": algo,
                    "hash": h,
                    "verdict": verdict.get("verdict", "unknown"),
                    "details": verdict,
                })
            except Exception as e:
                results.append({"path": path, "hash": h, "error": str(e)})
    except Exception as e:
        results.append({"path": target, "error": str(e)})

    return results
