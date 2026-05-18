"""
scanner.py — Pipeline de scan de sécurité parallèle

"""

import concurrent.futures
import socket

from app.application.services.tools.security_headers import scan_headers
from app.application.services.tools.ssl_labs         import scan_ssl
from app.application.services.tools.testssl          import scan_testssl
from app.application.services.tools.virustotal       import scan_virustotal
from app.application.services.tools.safe_browsing    import scan_safe_browsing
from app.application.services.tools.urlscan          import scan_urlscan
from app.application.services.tools.shodan           import scan_shodan_internetdb
from app.application.services.tools.wappalyzer       import scan_wappalyzer
from app.application.services.tools.zap_scanner import run_zap_scan
from app.application.services.tools.nuclei_scanner import scan_nuclei


# ─────────────────────────────────────────────────────────────────────────────
# Utilitaires internes
# ─────────────────────────────────────────────────────────────────────────────

def _resolve_ip(url: str) -> str | None:
    """
    Résout l'adresse IP de l'hôte contenu dans l'URL.
    """
    try:
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname
        return socket.gethostbyname(hostname) if hostname else None
    except Exception:
        return None


def _safe_run(fn, *args):
    """
    Encapsule un appel de scanner pour garantir qu'aucune exception
    """
    try:
        return fn(*args)
    except Exception as exc:
        return {"status": "failed", "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# Analyse SSL avec fallback automatique
# ─────────────────────────────────────────────────────────────────────────────

# Types d'erreurs pour lesquels le fallback n'apporterait aucune valeur ajoutée

_NO_FALLBACK_ERROR_TYPES = {"rate_limit", "timeout", "network"}


def _scan_ssl_with_fallback(url: str) -> dict:
    
    #Tente d'abord une analyse SSL via SSL Labs.
    #en cas d'erruer bascule automatiquement vers testssl.sh / Python natif.

    result = _safe_run(scan_ssl, url)

    if result.get("status") == "completed":
        result["_source"]       = "ssllabs"
        result["fallback_used"] = False
        return result

    # Pas de fallback pour les erreurs où une seconde tentative n'aiderait pas
    if result.get("error_type", "") in _NO_FALLBACK_ERROR_TYPES:
        result.setdefault("_source", "ssllabs")
        result["fallback_used"] = False
        return result

    # Fallback vers l'analyseur alternatif
    fallback = _safe_run(scan_testssl, url)
    fallback["_source"]       = "python_ssl"
    fallback["fallback_used"] = True
    return fallback


# ─────────────────────────────────────────────────────────────────────────────
# Scan complet — tous les outils lancés en parallèle
# ─────────────────────────────────────────────────────────────────────────────

def run_full_scan(url: str) -> dict:
    ip = _resolve_ip(url)
    report: dict = {"url": url, "status": "completed"}

    tasks = [
        ("headers",       scan_headers,          url),
        ("virustotal",    scan_virustotal,        url),
        ("safe_browsing", scan_safe_browsing,     url),
        ("urlscan",       scan_urlscan,           url),
        ("shodan",        scan_shodan_internetdb, ip),
        ("wappalyzer",    scan_wappalyzer,        url),
        ("zap",           run_zap_scan,           url),
        ("nuclei",        scan_nuclei,            url),
    ]


    executor = concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks) + 1)
    try:
        ssl_future = executor.submit(_scan_ssl_with_fallback, url)

        future_to_key: dict = {
            executor.submit(_safe_run, fn, *args): key
            for key, fn, *args in tasks
        }
        future_to_key[ssl_future] = "ssl"

        completed_futures = set()
        try:
            for future in concurrent.futures.as_completed(
                future_to_key, timeout=560
            ):
                key = future_to_key[future]
                completed_futures.add(future)
                try:
                    report[key] = future.result()
                except Exception as exc:
                    report[key] = {"status": "failed", "error": str(exc)}

        except concurrent.futures.TimeoutError:
            for future, key in future_to_key.items():
                if future not in completed_futures:
                    if future.done():
                        try:
                            report[key] = future.result()
                        except Exception as exc:
                            report[key] = {"status": "failed", "error": str(exc)}
                    else:
                        report[key] = {
                            "status":     "failed",
                            "error_type": "timeout",
                            "error":      f"Scanner '{key}' a dépassé le délai de 360s",
                        }
                        future.cancel()

    finally:

        executor.shutdown(wait=False, cancel_futures=True)

    return report