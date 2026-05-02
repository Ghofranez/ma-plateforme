import httpx
import base64
from app.core.config import settings


def scan_virustotal(url: str) -> dict:
    """
    Analyse une URL via l'API VirusTotal v3.
    Vérifie si l'URL est détectée comme malveillante par 90+ moteurs antivirus.
    Clé API requise : VIRUSTOTAL_KEY dans .env
    """
    try:
        if not settings.VIRUSTOTAL_KEY:
            return {"status": "disabled", "error": "Clé API VirusTotal manquante"}

        headers = {
            "x-apikey": settings.VIRUSTOTAL_KEY,
            "Content-Type": "application/x-www-form-urlencoded",
        }

        with httpx.Client(timeout=30) as client:

            # Étape 1 — Soumettre l'URL pour analyse
            res = client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url}
            )

            if res.status_code != 200:
                return {"status": "failed", "error": f"Erreur soumission : {res.status_code}"}

            # Récupérer l'ID de l'analyse
            analysis_id = res.json().get("data", {}).get("id", "")
            if not analysis_id:
                return {"status": "failed", "error": "ID analyse non reçu"}

            # Étape 2 — Récupérer le résultat de l'analyse
            res2 = client.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers
            )

            if res2.status_code != 200:
                return {"status": "failed", "error": f"Erreur résultat : {res2.status_code}"}

            data   = res2.json().get("data", {})
            attrs  = data.get("attributes", {})
            stats  = attrs.get("stats", {})

            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless   = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total      = malicious + suspicious + harmless + undetected

            # Déterminer le niveau de risque
            if malicious >= 5:
                risk_level = "Critique"
            elif malicious >= 2 or suspicious >= 5:
                risk_level = "Suspect"
            elif malicious == 1 or suspicious >= 1:
                risk_level = "Attention"
            else:
                risk_level = "Sain"

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
                "permalink":  f"https://www.virustotal.com/gui/url/{base64.urlsafe_b64encode(url.encode()).decode().strip('=')}"
            }

    except Exception as e:
        return {"status": "failed", "error": str(e)}