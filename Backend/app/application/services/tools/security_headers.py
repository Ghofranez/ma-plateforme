import httpx

# ── Headers vérifiés : X-Frame-Options, CSP, HSTS, etc. ──────

def scan_headers(url: str) -> dict:
    """
    Vérifie les headers HTTP de sécurité
    
    """
    try:
        with httpx.Client(timeout=15, follow_redirects=True) as client:
            res = client.get(url)
            headers = res.headers

            # Headers de sécurité à vérifier
            checks = {
                "X-Frame-Options":           headers.get("x-frame-options"),            # anti-clickjacking
                "X-Content-Type-Options":    headers.get("x-content-type-options"),
                "Strict-Transport-Security": headers.get("strict-transport-security"),  # force HTTPS
                "Content-Security-Policy":   headers.get("content-security-policy"),    # anti-XSS
                "X-XSS-Protection":          headers.get("x-xss-protection"),
                "Referrer-Policy":           headers.get("referrer-policy"),
            }

            present = [k for k, v in checks.items() if v]
            missing = [k for k, v in checks.items() if not v]
            score   = len(present)

            if score >= 5:   grade = "A"
            elif score >= 3: grade = "B"
            elif score >= 1: grade = "C"
            else:            grade = "F"

            return {
                "status":  "completed",
                "grade":   grade,
                "score":   f"{score}/6",
                "present": present,
                "missing": missing,
                "safe":    score >= 4
            }

    except Exception as e:
        return {"status": "failed", "error": str(e)}