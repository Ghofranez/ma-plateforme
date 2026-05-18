# availability.py — Vérifie si un site est accessible

import requests
import time

def check_availability(url: str) -> dict:
    start = time.time()
    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        elapsed = int((time.time() - start) * 1000)
        return {
            "status":      "completed",
            "is_up":       response.status_code < 500,
            "status_code": response.status_code,
            "response_ms": elapsed,
        }

    except requests.exceptions.Timeout:
        return {
            "status":  "completed",
            "is_up":   False,
            "reason":  "timeout",
        }

    except requests.exceptions.ConnectionError:
        return {
            "status":  "completed",
            "is_up":   False,
            "reason":  "connection_error",
        }

    except Exception as e:
        return {
            "status": "failed",
            "is_up":  False,
            "error":  str(e),
        }