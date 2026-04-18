# outils de scan — activés progressivement

def run_full_scan(url: str) -> dict:
    """
    Lance tous les outils de scan sur l'URL.
    Les outils sont désactivés pour l'instant — à activer un par un.
    """
    return {
        "url": url,
        "reputation":      {"status": "disabled"},
        "headers":         {"status": "disabled"},
        "vulnerabilities": {"status": "disabled", "high": 0},
        "ip_dns":          {"status": "disabled"},
    }

# ── À activer quand les clés API sont prêtes ──────────────────
# import httpx
# from app.core.config import settings
#
# def scan_virustotal(url: str) -> dict: ...
# def scan_headers(url: str) -> dict: ...
# def scan_zap(url: str) -> dict: ...
# def scan_ipqs(url: str) -> dict: ...