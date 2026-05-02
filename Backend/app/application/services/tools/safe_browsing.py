import httpx
from app.core.config import settings

def scan_safe_browsing(url: str) -> dict:
    """
    Vérifie si l'URL est dans les bases de données Google Safe Browsing.
    Détecte : malware, phishing, unwanted software, social engineering.

    """
    try:
        if not getattr(settings, "GOOGLE_SAFE_BROWSING_KEY", None):
            return {"status": "disabled", "error": "Clé API Google Safe Browsing manquante"}

        api_url = (
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
            f"?key={settings.GOOGLE_SAFE_BROWSING_KEY}"
        )

        payload = {
            "client": {
                "clientId": "ma-plateforme",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",       # phishing
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        with httpx.Client(timeout=15) as client:
            res = client.post(api_url, json=payload)

            if res.status_code != 200:
                return {"status": "failed", "error": f"Erreur API : {res.status_code}"}

            data = res.json()
            matches = data.get("matches", [])

            if not matches:
                return {
                    "status": "completed",
                    "safe": True,
                    "threats": [],
                    "risk_level": "Sain",
                    "message": "Aucune menace détectée par Google Safe Browsing"
                }

            # Extraire les types de menaces détectées
            threat_types = {m.get("threatType", "UNKNOWN") for m in matches}

            threat_labels = {
                "MALWARE": "Malware",
                "SOCIAL_ENGINEERING": "Phishing / Ingénierie sociale",
                "UNWANTED_SOFTWARE": "Logiciel indésirable",
                "POTENTIALLY_HARMFUL_APPLICATION": "Application potentiellement dangereuse",
            }

            threats_fr = [threat_labels.get(t, t) for t in threat_types]

            return {
                "status": "completed",
                "safe": False,
                "threats": threats_fr,
                "risk_level": "Critique",
                "message": f"URL blacklistée par Google — {len(threats_fr)} menace(s) détectée(s)"
            }

    except Exception as e:
        return {"status": "failed", "error": str(e)}
