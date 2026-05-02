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


# ─────────────────────────────────────────────────────────────────────────────
# Utilitaires internes
# ─────────────────────────────────────────────────────────────────────────────

def _resolve_ip(url: str) -> str | None:
    """
    Résout l'adresse IP de l'hôte contenu dans l'URL.
    Retourne None si la résolution DNS échoue ou si l'URL est malformée.
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
    ne remonte et n'interrompt le pipeline global.
    En cas d'erreur, retourne un dict uniforme avec status='failed'.
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
    """
    Tente d'abord une analyse SSL via SSL Labs.
    Si elle échoue pour une raison récupérable (erreur serveur, indisponibilité),
    bascule automatiquement vers testssl.sh / Python natif.
    Les erreurs non récupérables (rate limit, timeout, réseau) ne déclenchent pas de fallback.
    """
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
    """
    Lance l'ensemble des scanners de sécurité en parallèle et retourne
    un rapport consolidé. Chaque outil est isolé : une erreur individuelle
    n'empêche pas les autres de terminer.

    """
    ip = _resolve_ip(url)

    report: dict = {"url": url, "status": "completed"}

    # Chaque entrée : (clé dans le rapport, fonction scanner, *arguments)
    tasks = [
        ("headers",       scan_headers,          url),
        ("virustotal",    scan_virustotal,        url),
        ("safe_browsing", scan_safe_browsing,     url),
        #("openphish",     scan_openphish,         url),
        ("urlscan",       scan_urlscan,           url),
        ("shodan",        scan_shodan_internetdb, ip),
        ("wappalyzer",    scan_wappalyzer,        url),
    ]

    #  worker pour le scan SSL qui tourne séparément (gestion du fallback)
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks) + 1) as executor:

        # SSL lancé en premier avec sa propre logique de fallback
        ssl_future = executor.submit(_scan_ssl_with_fallback, url)

        # Tous les autres outils soumis via _safe_run
        future_to_key: dict = {
            executor.submit(_safe_run, fn, *args): key
            for key, fn, *args in tasks
        }
        future_to_key[ssl_future] = "ssl"

        for future in concurrent.futures.as_completed(future_to_key):
            key = future_to_key[future]
            try:
                report[key] = future.result()
            except Exception as exc:
                report[key] = {"status": "failed", "error": str(exc)}

    return report