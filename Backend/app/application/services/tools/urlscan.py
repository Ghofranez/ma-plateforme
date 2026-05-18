import ssl
import socket
import time
import requests
from datetime import datetime, timezone
from urllib.parse import urlparse
from app.core.config import settings

URLSCAN_SUBMIT  = "https://urlscan.io/api/v1/scan/"
URLSCAN_RESULT  = "https://urlscan.io/api/v1/result/"
POLL_INTERVAL_S = 5
MAX_ATTEMPTS    = 12


def get_ssl_info(hostname: str) -> dict:
    #Récupère les infos SSL directement depuis le certificat du serveur.
    try:
        ctx = ssl.create_default_context()

        #  Connexion propre — timeout AVANT la connexion
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()

        if not cert:
            return {
                "valid":    False,
                "expired":  False,
                "warning":  False,
                "daysLeft": None,
                "error":    "Certificat vide",
            }

        not_after  = cert.get("notAfter", "")
        not_before = cert.get("notBefore", "")

        #  Parse de la date d'expiration
        expire_date = datetime.strptime(
            not_after, "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)

        start_date = datetime.strptime(
            not_before, "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)

        now        = datetime.now(timezone.utc)
        days_left  = (expire_date - now).days
        is_expired = days_left <= 0
        is_warning = 0 < days_left <= 14

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer",  []))

        return {
            "valid":     not is_expired,
            "expired":   is_expired,
            "warning":   is_warning,
            "daysLeft":  days_left,
            "expiresOn": expire_date.strftime("%Y-%m-%d"),
            "issuedOn":  start_date.strftime("%Y-%m-%d"),
            "subject":   subject.get("commonName", hostname),
            "issuer":    issuer.get("organizationName", "Unknown"),
            "protocol":  "TLS",
        }

    except ssl.SSLCertVerificationError as e:
        # Essayer quand même de lire le cert sans vérification
        try:
            ctx_noverify = ssl.create_default_context()
            ctx_noverify.check_hostname = False
            ctx_noverify.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with ctx_noverify.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    cert = tls_sock.getpeercert()
            if cert:
                not_after   = cert.get("notAfter", "")
                expire_date = datetime.strptime(
                    not_after, "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)
                now       = datetime.now(timezone.utc)
                days_left = (expire_date - now).days
                return {
                    "valid":     False,   # invalide car non vérifié
                    "expired":   days_left <= 0,
                    "warning":   0 < days_left <= 14,
                    "daysLeft":  days_left,
                    "expiresOn": expire_date.strftime("%Y-%m-%d"),
                    "issuer":    "Non vérifié",
                    "error":     "Certificat auto-signé ou invalide",
                }
        except Exception:
            pass
        return {
            "valid":    False,
            "expired":  False,
            "warning":  False,
            "daysLeft": None,
            "error":    f"Certificat SSL invalide : {e}",
        }

    except ssl.SSLError as e:
        return {
            "valid":    False,
            "expired":  False,
            "warning":  False,
            "daysLeft": None,
            "error":    f"Erreur SSL : {e}",
        }
    except (socket.timeout, socket.gaierror) as e:
        return {
            "valid":    False,
            "expired":  False,
            "warning":  False,
            "daysLeft": None,
            "error":    f"Connexion impossible : {e}",
        }
    except Exception as e:
        return {
            "valid":    False,
            "expired":  False,
            "warning":  False,
            "daysLeft": None,
            "error":    f"Erreur inattendue : {e}",
        }


def scan_urlscan(url: str) -> dict:
 #Soumet une URL à urlscan.io et retourne le résultat complet.

    api_key = getattr(settings, "URLSCAN_API_KEY", "") or ""
    if not api_key:
        return {"status": "disabled", "error": "URLSCAN_API_KEY non configurée"}

    headers = {
        "API-Key":      api_key,
        "Content-Type": "application/json",
    }

    # ── 1. Calcul SSL fiable avant la soumission ──────────────────────────
    hostname = urlparse(url).hostname or ""
    ssl_info = get_ssl_info(hostname) if hostname else {
        "valid":    False,
        "daysLeft": None,
        "error":    "Hostname introuvable",
    }

    # ── 2. Soumission à urlscan.io ────────────────────────────────────────
    try:
        submit_resp = requests.post(
            URLSCAN_SUBMIT,
            json={
                "url":        url,
                "visibility": "unlisted",
                "tags":       ["security-platform"],
            },
            headers=headers,
            timeout=15,
        )
    except requests.RequestException as exc:
        return {"status": "failed", "error": f"Soumission urlscan échouée : {exc}"}

    if submit_resp.status_code != 200:
        return {
            "status": "failed",
            "error":  f"urlscan HTTP {submit_resp.status_code} : {submit_resp.text[:200]}",
        }

    uuid = submit_resp.json().get("uuid")
    if not uuid:
        return {"status": "failed", "error": "UUID manquant dans la réponse urlscan"}

    # ── 3. Polling du résultat ────────────────────────────────────────────
    for attempt in range(MAX_ATTEMPTS):
        time.sleep(POLL_INTERVAL_S)

        try:
            poll_resp = requests.get(
                f"{URLSCAN_RESULT}{uuid}/",
                headers={"API-Key": api_key},
                timeout=15,
            )
        except requests.RequestException:
            continue

        if poll_resp.status_code == 404:
            continue   # scan encore en cours

        if poll_resp.status_code != 200:
            return {
                "status": "failed",
                "error":  f"urlscan result HTTP {poll_resp.status_code}",
            }

        data = poll_resp.json()

        return {
            "status":    "completed",
            "uuid":      uuid,
            "reportUrl": f"https://urlscan.io/result/{uuid}/",

            # ── Verdict global ────────────────────────────────────────────
            "verdict": {
                "malicious": data.get("verdicts", {}).get("overall", {}).get("malicious", False),
                "score":     data.get("verdicts", {}).get("overall", {}).get("score", 0),
                "tags":      data.get("verdicts", {}).get("overall", {}).get("tags", []),
                "brands":    data.get("verdicts", {}).get("urlscan", {}).get("brands", []),
            },

            # ── Infos page ────────────────────────────────────────────────
            "page": {
                "domain":  data.get("page", {}).get("domain"),
                "ip":      data.get("page", {}).get("ip"),
                "country": data.get("page", {}).get("country"),
                "server":  data.get("page", {}).get("server"),
                "title":   data.get("page", {}).get("title"),

                "tlsValidDays":  ssl_info.get("daysLeft"),
                "tlsExpired":    ssl_info.get("expired", False),
                "tlsWarning":    ssl_info.get("warning", False),
                "tlsExpiresOn":  ssl_info.get("expiresOn"),
                "tlsIssuer":     ssl_info.get("issuer"),
                "tlsValid":      ssl_info.get("valid", False),
            },

            # ── Statistiques ──────────────────────────────────────────────
            "stats": {
                "requests":      data.get("stats", {}).get("requests", 0),
                "uniqueDomains": data.get("stats", {}).get("uniqDomains", 0),
                "uniqueIPs":     data.get("stats", {}).get("uniqIPs", 0),
            },
        }

    # ── Timeout ───────────────────────────────────────────────────────────
    return {
        "status": "failed",
        "error":  f"urlscan timeout — scan non terminé après {MAX_ATTEMPTS * POLL_INTERVAL_S}s",
        "uuid":   uuid,
        # Retourner quand même les infos SSL même si urlscan timeout
        "page": {
            "tlsValidDays": ssl_info.get("daysLeft"),
            "tlsExpired":   ssl_info.get("expired", False),
            "tlsWarning":   ssl_info.get("warning", False),
            "tlsExpiresOn": ssl_info.get("expiresOn"),
            "tlsIssuer":    ssl_info.get("issuer"),
            "tlsValid":     ssl_info.get("valid", False),
        },
    }