"""
tools/ssl.py — Analyse SSL via SSL Labs API v3
"""

import time
import datetime
import requests
from urllib.parse import urlparse

SSL_LABS_API = "https://api.ssllabs.com/api/v3/analyze"


def scan_ssl(url: str) -> dict:
    try:
        parsed = urlparse(url)
        host   = parsed.hostname

        if not host:
            return {"status": "failed", "error_type": "invalid_url", "_source": "ssllabs"}

        # HTTP pur → pas de SSL
        if parsed.scheme == "http" and not parsed.port:
            return {
                "status":     "failed",
                "error_type": "no_tls",
                "error":      "http_no_tls",
                "message":    "Ce site utilise HTTP et non HTTPS — aucun chiffrement actif.",
                "_source":    "ssllabs",
            }

        # Lancer le scan
        requests.get(
            SSL_LABS_API,
            params={"host": host, "startNew": "on", "all": "done"},
            timeout=15,
        )

        start_time = time.time()

        while True:
            r = requests.get(
                SSL_LABS_API,
                params={"host": host, "all": "done"},
                timeout=15,
            )

            if r.status_code == 429:
                return {"status": "failed", "error_type": "rate_limit", "_source": "ssllabs"}

            if r.status_code != 200:
                return {"status": "failed", "error_type": "network", "_source": "ssllabs"}

            data   = r.json()
            status = data.get("status")

            if status == "READY":
                endpoints = data.get("endpoints", [])
                if not endpoints:
                    return {"status": "failed", "error_type": "no_endpoint", "_source": "ssllabs"}

                ep      = endpoints[0]
                details = ep.get("details") or {}
                grade   = ep.get("grade", "N/A")

                # ── Certificat ──────────────────────────────────────────────
                cert_raw      = details.get("cert") or {}
                not_after     = cert_raw.get("notAfter")       # timestamp ms
                days_remaining = None
                expiry_str    = None
                issuer        = None

                if not_after:
                    try:
                        expiry_dt     = datetime.datetime.fromtimestamp(
                            not_after / 1000, tz=datetime.timezone.utc
                        )
                        now           = datetime.datetime.now(datetime.timezone.utc)
                        days_remaining = (expiry_dt - now).days
                        expiry_str    = expiry_dt.strftime("%Y-%m-%d")
                    except Exception:
                        pass

                # Émetteur depuis la chaîne de certificats
                chain = details.get("chain", {}).get("certs", [])
                if chain and len(chain) > 1:
                    issuer = chain[-1].get("subject", "")
                elif cert_raw.get("issuerSubject"):
                    issuer = cert_raw["issuerSubject"]

                cert_info = {
                    "verified":      not bool(cert_raw.get("issues")),
                    "daysRemaining": days_remaining,
                    "expiry":        expiry_str,
                    "issuer":        issuer,
                    "commonName":    cert_raw.get("commonNames", [host])[0] if cert_raw.get("commonNames") else host,
                    "altNames":      cert_raw.get("altNames", []),
                }

                # ── Protocoles supportés ────────────────────────────────────
                raw_protocols = details.get("protocols", [])
                protocols = [
                    f"{p.get('name', 'TLS')} {p.get('version', '')}" .strip()
                    for p in raw_protocols
                ]

                # ── Suites de chiffrement ───────────────────────────────────
                suites_raw = details.get("suites", [])
                # suites peut être une liste de dicts ou une liste de listes
                suites = []
                for s in suites_raw:
                    if isinstance(s, dict):
                        # SSL Labs v3 : {"list": [...], "preference": bool}
                        for suite in s.get("list", []):
                            if isinstance(suite, dict):
                                suites.append({"name": suite.get("name", "")})
                    elif isinstance(s, str):
                        suites.append({"name": s})

                # ── Vulnérabilités ──────────────────────────────────────────
                cves = []
                vulns_map = {
                    "heartbleed": ("HEARTBLEED", "Vulnérable à Heartbleed (CVE-2014-0160)"),
                    "poodle":     ("POODLE",     "Vulnérable à POODLE (CVE-2014-3566)"),
                    "freak":      ("FREAK",      "Vulnérable à FREAK (CVE-2015-0204)"),
                    "logjam":     ("LOGJAM",     "Vulnérable à Logjam (CVE-2015-4000)"),
                    "beast":      ("BEAST",      "Vulnérable à BEAST (CVE-2011-3389)"),
                    "rc4":        ("RC4",        "Chiffrement RC4 supporté — cassé cryptographiquement"),
                }
                for key, (cve_id, detail) in vulns_map.items():
                    val = details.get(key)
                    if val and val not in (0, False, "0"):
                        cves.append({"id": cve_id, "detail": detail})

                # openSslCcs == 2 → vulnérable
                if details.get("openSslCcs") == 2:
                    cves.append({"id": "OpenSSL CCS", "detail": "Injection OpenSSL CCS (CVE-2014-0224)"})

                # poodleTls == 2 → vulnérable
                if details.get("poodleTls") == 2:
                    cves.append({"id": "POODLE TLS", "detail": "POODLE affectant TLS"})

                # ── Safe : déduit du grade ──────────────────────────────────
                safe = grade.upper() in ("A+", "A", "A-", "B")

                return {
                    "status":    "completed",
                    "_source":   "ssllabs",
                    "host":      host,
                    "grade":     grade,
                    "safe":      safe,
                    "protocols": protocols,
                    "suites":    suites,
                    "cves":      cves,
                    "cert":      cert_info,
                    # Données brutes pour SslLabsDetail côté frontend
                    "endpoints": [{
                        "grade":     grade,
                        "ipAddress": ep.get("ipAddress", ""),
                        "details": {
                            "protocols":      raw_protocols,
                            "suites":         suites_raw,
                            "heartbleed":     details.get("heartbleed"),
                            "poodle":         details.get("poodle"),
                            "freak":          details.get("freak"),
                            "logjam":         details.get("logjam"),
                            "beast":          details.get("beast"),
                            "rc4":            details.get("rc4"),
                            "openSslCcs":     details.get("openSslCcs"),
                            "poodleTls":      details.get("poodleTls"),
                            "ticketBleed":    details.get("ticketBleed"),
                            "bleichenbacher": details.get("bleichenbacher"),
                        },
                    }],
                }

            if status == "ERROR":
                return {"status": "failed", "error_type": "ssllabs_error", "_source": "ssllabs"}

            if time.time() - start_time > 180:
                return {"status": "failed", "error_type": "timeout", "_source": "ssllabs"}

            time.sleep(8)

    except requests.exceptions.Timeout:
        return {"status": "failed", "error_type": "timeout", "_source": "ssllabs"}
    except Exception as e:
        return {"status": "failed", "error_type": "unknown", "error": str(e), "_source": "ssllabs"}