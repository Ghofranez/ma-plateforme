"""
tools/testssl.py — Analyse SSL/TLS native Python (sans Docker)

Rôle : analyse le certificat et le chiffrement d'un site directement
via les modules ssl + socket + cryptography de Python.

 Fonctionne dans tous les environnements (workers Celery, conteneurs Docker, CI…)
 Aucune dépendance externe (pas de Docker, pas de binaire tiers)
 Fallback automatique quand SSL Labs échoue
"""

import ssl
import socket
import datetime
from urllib.parse import urlparse


# ─────────────────────────────────────────────────────────────────────────────
# Point d'entrée principal
# ─────────────────────────────────────────────────────────────────────────────

def scan_testssl(url: str) -> dict:
    """
    Analyse SSL/TLS d'une URL via les modules Python natifs.
    Retourne un dict au format identique à scan_ssl (SSL Labs).
    """
    try:
        parsed   = urlparse(url)
        hostname = parsed.hostname
        port     = parsed.port or (443 if parsed.scheme == "https" else 80)

        if not hostname:
            return {"status": "failed", "error": "Hostname invalide"}

        # HTTP pur → pas de SSL à analyser
        if parsed.scheme == "http" and not parsed.port:
            return {
                "status": "failed",
                "error":  "http_no_tls",
                "error_type": "no_tls",
                "message": "Ce site utilise HTTP et non HTTPS — aucun chiffrement actif.",
            }

        return _analyze_ssl(hostname, port)

    except Exception as exc:
        return {"status": "failed", "error": str(exc), "_source": "python_ssl"}


# ─────────────────────────────────────────────────────────────────────────────
# Analyse SSL complète
# ─────────────────────────────────────────────────────────────────────────────

def _analyze_ssl(hostname: str, port: int) -> dict:
    """Connecte en TLS et inspecte le certificat + la configuration."""

    # ── 1. Connexion TLS avec vérification stricte ───────────────────────────
    context_strict = ssl.create_default_context()
    cert_verified  = True
    cert_info      = {}
    protocol_used  = "unknown"
    cipher_info    = {}

    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context_strict.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                protocol_used = tls_sock.version() or "unknown"
                cipher_info   = tls_sock.cipher() or {}
                raw_cert      = tls_sock.getpeercert()
                cert_info     = _parse_cert(raw_cert)
    except ssl.SSLCertVerificationError:
        cert_verified = False
        # On retente sans vérification pour quand même lire les infos
        cert_info, protocol_used, cipher_info = _connect_no_verify(hostname, port)
    except ssl.SSLError as e:
        return {
            "status":     "failed",
            "error":      "ssl_error",
            "error_type": "ssl_error",
            "message":    str(e),
            "_source":    "python_ssl",
        }
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {
            "status":     "failed",
            "error":      "connection_failed",
            "error_type": "network",
            "message":    str(e),
            "_source":    "python_ssl",
        }

    # ── 2. Test des protocoles anciens (SSLv2/v3/TLS 1.0/1.1) ───────────────
    weak_protocols = _check_weak_protocols(hostname, port)

    # ── 3. Calcul du grade ───────────────────────────────────────────────────
    grade = _compute_grade(
        cert_verified   = cert_verified,
        cert_info       = cert_info,
        protocol_used   = protocol_used,
        cipher_info     = cipher_info,
        weak_protocols  = weak_protocols,
    )

    # ── 4. CVEs simulées (basées sur protocoles faibles détectés) ────────────
    cves = _build_cve_list(weak_protocols, cipher_info)

    return {
        "status":    "completed",
        "host":      hostname,
        "port":      port,
        "grade":     grade,
        "safe":      grade in ("A+", "A", "A-", "B"),
        "protocols": _supported_protocols(protocol_used, weak_protocols),
        "cves":      cves,
        "cert": {
            "commonName":    cert_info.get("commonName", hostname),
            "expiry":        cert_info.get("expiry", "unknown"),
            "daysRemaining": cert_info.get("daysRemaining"),
            "issuer":        cert_info.get("issuer", "unknown"),
            "verified":      cert_verified,
        },
        "_source": "python_ssl",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Helpers de connexion
# ─────────────────────────────────────────────────────────────────────────────

def _connect_no_verify(hostname: str, port: int) -> tuple[dict, str, tuple]:
    """Connexion TLS sans vérification du certificat (pour lire les infos malgré tout)."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                raw_cert = tls_sock.getpeercert()
                return (
                    _parse_cert(raw_cert),
                    tls_sock.version() or "unknown",
                    tls_sock.cipher() or {},
                )
    except Exception:
        return {}, "unknown", {}


def _check_weak_protocols(hostname: str, port: int) -> list[str]:
    """
    Tente de se connecter avec TLS 1.0 et TLS 1.1 pour détecter leur support.
    TLS 1.2 et 1.3 sont considérés sûrs et ne sont pas listés ici.
    """
    weak = []
    for proto_name, ssl_version in [
        ("TLS1.0", ssl.TLSVersion.TLSv1),
        ("TLS1.1", ssl.TLSVersion.TLSv1_1),
    ]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.maximum_version = ssl_version
            ctx.minimum_version = ssl_version
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    weak.append(proto_name)
        except (ssl.SSLError, AttributeError, OSError):
            # AttributeError si TLSVersion n'est pas dispo sur cette version Python/OpenSSL
            pass
    return weak


# ─────────────────────────────────────────────────────────────────────────────
# Parsing du certificat
# ─────────────────────────────────────────────────────────────────────────────

def _parse_cert(raw_cert: dict) -> dict:
    """Extrait les infos utiles du certificat brut retourné par Python ssl."""
    if not raw_cert:
        return {}

    # Common Name
    subject = dict(x[0] for x in raw_cert.get("subject", []))
    cn      = subject.get("commonName", "")

    # Issuer
    issuer_dict = dict(x[0] for x in raw_cert.get("issuer", []))
    issuer      = issuer_dict.get("organizationName", issuer_dict.get("commonName", "unknown"))

    # Expiry
    not_after     = raw_cert.get("notAfter", "")
    expiry_str    = not_after
    days_remaining = None
    try:
        expiry_dt     = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        expiry_dt     = expiry_dt.replace(tzinfo=datetime.timezone.utc)
        now           = datetime.datetime.now(datetime.timezone.utc)
        days_remaining = (expiry_dt - now).days
        expiry_str    = expiry_dt.strftime("%Y-%m-%d")
    except Exception:
        pass

    return {
        "commonName":    cn,
        "issuer":        issuer,
        "expiry":        expiry_str,
        "daysRemaining": days_remaining,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Grade et CVEs
# ─────────────────────────────────────────────────────────────────────────────

def _compute_grade(
    cert_verified:  bool,
    cert_info:      dict,
    protocol_used:  str,
    cipher_info:    tuple | dict,
    weak_protocols: list[str],
) -> str:
    score = 100

    # Certificat invalide / non vérifié
    if not cert_verified:
        score -= 40

    # Certificat expiré ou proche expiration
    days = cert_info.get("daysRemaining")
    if days is not None:
        if days < 0:
            score -= 30   # expiré
        elif days < 14:
            score -= 15   # expire très bientôt

    # Protocoles anciens acceptés
    if "TLS1.0" in weak_protocols:
        score -= 15
    if "TLS1.1" in weak_protocols:
        score -= 10

    # Chiffrement faible
    if isinstance(cipher_info, (tuple, list)) and len(cipher_info) >= 1:
        cipher_name = cipher_info[0] if isinstance(cipher_info, (tuple, list)) else ""
        if any(weak in cipher_name for weak in ["RC4", "DES", "NULL", "EXPORT", "anon"]):
            score -= 30
        elif "3DES" in cipher_name:
            score -= 15

    score = max(0, score)

    if score >= 95: return "A+"
    if score >= 85: return "A"
    if score >= 75: return "A-"
    if score >= 65: return "B"
    if score >= 50: return "C"
    if score >= 35: return "D"
    return "F"


def _supported_protocols(current: str, weak: list[str]) -> list[str]:
    """Construit la liste des protocoles supportés."""
    protocols = []
    if "TLS1.0" in weak:  protocols.append("TLS1.0")
    if "TLS1.1" in weak:  protocols.append("TLS1.1")
    if current in ("TLSv1.2", "TLS 1.2"): protocols.append("TLS1.2")
    if current in ("TLSv1.3", "TLS 1.3"): protocols.append("TLS1.3")
    if not protocols and current != "unknown":
        protocols.append(current)
    return protocols


def _build_cve_list(weak_protocols: list[str], cipher_info: tuple | dict) -> list[dict]:
    """Associe les protocoles faibles détectés à leurs CVEs / vulnérabilités connues."""
    cves = []

    if "TLS1.0" in weak_protocols:
        cves.append({
            "id":     "BEAST / POODLE (TLS 1.0)",
            "detail": "TLS 1.0 est supporté — protocole obsolète vulnérable à BEAST et POODLE.",
        })

    if "TLS1.1" in weak_protocols:
        cves.append({
            "id":     "TLS 1.1 obsolète",
            "detail": "TLS 1.1 est supporté — protocole obsolète, désactivé par les navigateurs modernes.",
        })

    if isinstance(cipher_info, (tuple, list)) and len(cipher_info) >= 1:
        cipher_name = cipher_info[0] if isinstance(cipher_info, (tuple, list)) else ""
        if "RC4" in cipher_name:
            cves.append({"id": "RC4", "detail": "Chiffrement RC4 détecté — cassé cryptographiquement."})
        if "3DES" in cipher_name or "DES" in cipher_name:
            cves.append({"id": "SWEET32", "detail": "Chiffrement DES/3DES détecté — vulnérable à SWEET32."})

    return cves