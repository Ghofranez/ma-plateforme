import requests

INTERNETDB_URL  = "https://internetdb.shodan.io"
DANGEROUS_PORTS = {21, 23, 3306, 5432, 6379, 27017, 9200}


def scan_shodan_internetdb(ip: str | None) -> dict:
    if not ip:
        return {
            "status":    "failed",
            "error":     "IP introuvable — résolution DNS impossible",
            "known":     False,
            "openPorts": [],
            "cves":      [],
        }

    try:
        resp = requests.get(f"{INTERNETDB_URL}/{ip}", timeout=10)
    except requests.RequestException as exc:
        return {"status": "failed", "error": str(exc), "ip": ip}

    # 404 = IP non indexée par Shodan → peu exposée, pas d'alerte
    if resp.status_code == 404:
        return {
            "status":    "completed",
            "ip":        ip,
            "known":     False,
            "openPorts": [],
            "cves":      [],
            "tags":      [],
            "hostnames": [],
            "riskLevel": "low",
            "message":   "IP non indexée par Shodan — exposition minimale détectée",
        }

    if resp.status_code != 200:
        return {"status": "failed", "error": f"Shodan HTTP {resp.status_code}", "ip": ip}

    data       = resp.json()
    open_ports = data.get("ports", [])
    cves       = data.get("vulns", [])
    risky      = [p for p in open_ports if p in DANGEROUS_PORTS]

    risk_level = (
        "high"   if len(cves) >= 3  else
        "medium" if len(cves) >= 1 or risky else
        "low"
    )

    return {
        "status":    "completed",
        "ip":        ip,
        "known":     True,
        "openPorts": open_ports,
        "cves":      cves,
        "tags":      data.get("tags",      []),
        "hostnames": data.get("hostnames", []),
        "riskLevel": risk_level,
        "riskyPorts": risky,
        "message":   f"{len(open_ports)} port(s) ouverts — {len(cves)} CVE(s) détecté(s)",
    }