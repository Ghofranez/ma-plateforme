import httpx
import base64
import time
from app.core.config import settings

def scan_virustotal(url: str) -> dict:

     #Analyse une URL via l'API VirusTotal v3.


    try:
        if not settings.VIRUSTOTAL_KEY:
            return {"status": "disabled", "error": "Clé API VirusTotal manquante"}

        headers = {
            "x-apikey":     settings.VIRUSTOTAL_KEY,
            "Content-Type": "application/x-www-form-urlencoded",
        }

        #  transport explicite avec résolveur DNS fiable (évite [Errno -3] dans Docker)
        transport = httpx.HTTPTransport(retries=3)

        with httpx.Client(timeout=45, transport=transport) as client:

            # ── Étape 1 : soumettre l'URL ──────────────────────────────────
            for attempt in range(3):
                try:
                    res = client.post(
                        "https://www.virustotal.com/api/v3/urls",
                        headers=headers,
                        data={"url": url},
                    )
                    break
                except (httpx.ConnectError, httpx.TimeoutException) as e:
                    if attempt == 2:
                        return {"status": "failed", "error": f"Connexion VirusTotal impossible : {e}"}
                    time.sleep(2 ** attempt)

            if res.status_code == 429:
                return {"status": "failed", "error": "Quota VirusTotal dépassé — réessayez dans 1 minute."}
            if res.status_code != 200:
                return {"status": "failed", "error": f"Erreur soumission : {res.status_code}"}

            analysis_id = res.json().get("data", {}).get("id", "")
            if not analysis_id:
                return {"status": "failed", "error": "ID analyse non reçu"}

            # ── Étape 2 : attendre et récupérer le résultat ────────────────
            # VirusTotal peut mettre quelques secondes à traiter
            for attempt in range(3):
                time.sleep(2)
                try:
                    res2 = client.get(
                        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                        headers=headers,
                    )
                    break
                except (httpx.ConnectError, httpx.TimeoutException) as e:
                    if attempt == 2:
                        return {"status": "failed", "error": f"Récupération résultat impossible : {e}"}
                    time.sleep(2 ** attempt)

            if res2.status_code != 200:
                return {"status": "failed", "error": f"Erreur résultat : {res2.status_code}"}

            data  = res2.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("stats", {})

            malicious  = stats.get("malicious",  0)
            suspicious = stats.get("suspicious", 0)
            harmless   = stats.get("harmless",   0)
            undetected = stats.get("undetected", 0)
            total      = malicious + suspicious + harmless + undetected

            if malicious >= 5:
                risk_level = "Critique"
            elif malicious >= 2 or suspicious >= 5:
                risk_level = "Suspect"
            elif malicious == 1 or suspicious >= 1:
                risk_level = "Attention"
            else:
                risk_level = "Sain"

            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

            return {
                "status":     "completed",
                "malicious":  malicious,
                "suspicious": suspicious,
                "harmless":   harmless,
                "undetected": undetected,
                "total":      total,
                "risk_level": risk_level,
                "safe":       malicious == 0 and suspicious == 0,
                "categories": attrs.get("categories", {}),
                "permalink":  f"https://www.virustotal.com/gui/url/{url_id}",
            }

    except Exception as e:
        return {"status": "failed", "error": str(e)}