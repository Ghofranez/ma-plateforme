import httpx
import time

SECURITY_HEADERS = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-XSS-Protection",
    "Referrer-Policy",
]

def scan_headers(url: str) -> dict:
    last_error = None

    for attempt in range(3):
        try:
            with httpx.Client(
                timeout=20,
                follow_redirects=True,
                verify=False,
                transport=httpx.HTTPTransport(retries=2),
            ) as client:
                res = client.get(url)
                headers = res.headers

                checks  = {h: headers.get(h.lower()) for h in SECURITY_HEADERS}
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
                    "safe":    score >= 4,
                }

        except Exception as e:
            last_error = str(e)
            if attempt < 2:
                time.sleep(2)

    return {"status": "failed", "error": last_error}