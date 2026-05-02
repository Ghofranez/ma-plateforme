import time
import requests
from app.core.config import settings


URLSCAN_SUBMIT  = "https://urlscan.io/api/v1/scan/"
URLSCAN_RESULT  = "https://urlscan.io/api/v1/result/"
POLL_INTERVAL_S = 5      # secondes entre chaque vérification
MAX_ATTEMPTS    = 12     # 12 × 5s = 60s max d'attente


def scan_urlscan(url: str) -> dict:
    api_key = getattr(settings, "URLSCAN_API_KEY", "") or ""

    if not api_key:
        return {"status": "disabled", "error": "URLSCAN_API_KEY non configurée"}

    headers = {
        "API-Key":      api_key,
        "Content-Type": "application/json",
    }

    # 1 — Soumission de l'URL
    try:
        submit_resp = requests.post(
            URLSCAN_SUBMIT,
            json={"url": url, "visibility": "unlisted", "tags": ["security-platform"]},
            headers=headers,
            timeout=15,
        )
    except requests.RequestException as exc:
        return {"status": "failed", "error": f"Soumission urlscan échouée : {exc}"}

    if submit_resp.status_code != 200:
        return {
            "status": "failed",
            "error": f"urlscan HTTP {submit_resp.status_code}",
        }

    uuid = submit_resp.json().get("uuid")
    if not uuid:
        return {"status": "failed", "error": "UUID manquant dans la réponse urlscan"}

    # 2 — Polling du résultat (le scan prend 10–45 secondes)
    for _ in range(MAX_ATTEMPTS):
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
            continue  # scan encore en cours
        if poll_resp.status_code != 200:
            return {"status": "failed", "error": f"urlscan result HTTP {poll_resp.status_code}"}

        data = poll_resp.json()

        return {
            "status":        "completed",
            "uuid":          uuid,
            "reportUrl":     f"https://urlscan.io/result/{uuid}/",
            "verdict": {
                "malicious": data.get("verdicts", {}).get("overall", {}).get("malicious", False),
                "score":     data.get("verdicts", {}).get("overall", {}).get("score", 0),
                "tags":      data.get("verdicts", {}).get("overall", {}).get("tags", []),
                "brands":    data.get("verdicts", {}).get("urlscan", {}).get("brands", []),
            },
            "page": {
                "domain":       data.get("page", {}).get("domain"),
                "ip":           data.get("page", {}).get("ip"),
                "country":      data.get("page", {}).get("country"),
                "server":       data.get("page", {}).get("server"),
                "title":        data.get("page", {}).get("title"),
                "tlsValidDays": data.get("page", {}).get("tlsValidDays"),
            },
            "stats": {
                "requests":      data.get("stats", {}).get("requests", 0),
                "uniqueDomains": data.get("stats", {}).get("uniqDomains", 0),
                "uniqueIPs":     data.get("stats", {}).get("uniqIPs", 0),
            },
        }

    return {
        "status": "failed",
        "error":  f"urlscan timeout — scan non terminé après {MAX_ATTEMPTS * POLL_INTERVAL_S}s",
        "uuid":   uuid,
    }