"""
nuclei_scanner.py — Scan de vulnérabilités avec
(configrration du serveur)

Nuclei cherche les portes mal fermées d'un site web :
   -fichiers secrets accessibles
   -interfaces d'administration sans protection
   -failles connues non corrigées
   -services accessibles sans mot de passe
=> d'apres des templates de détection
"""

import subprocess
import json
import logging
import shutil
import os
import time
import urllib.request
import requests
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_TEMPLATE_PATHS = [
    os.environ.get("NUCLEI_TEMPLATES_PATH", ""),
    "/home/celeryuser/nuclei-templates/",
    os.path.expanduser("~/nuclei-templates/"),
    "/root/nuclei-templates/",
]

NUCLEI_TAGS_FAST = ["misconfig", "exposure", "takeover", "panel"]
NUCLEI_TAGS_DEEP = ["rce", "ssrf", "cve", "unauth"]
NUCLEI_TAGS_ALL  = NUCLEI_TAGS_FAST + NUCLEI_TAGS_DEEP
NUCLEI_SEVERITIES = ["critical", "high", "medium"]

_NUCLEI_STDERR_IGNORE = [
    "[INF]", "[WRN] Found",
    "nuclei-templates",
    "Use -ud flag",
    "update",
    "Current nuclei",
    "templates loaded",
    "No results",
    "Skipping",
    "resumed",
    "Using",
    "[DBG]",
]

PROFILES = {
    "fast": {
        "timeout":        10,
        "rate_limit":     20,
        "bulk_size":      50,
        "concurrency":    20,
        "retries":        1,
        "max_host_error": 3,
        "phase_timeout":  150,
    },
    "medium": {
        "timeout":        15,
        "rate_limit":     10,
        "bulk_size":      25,
        "concurrency":    10,
        "retries":        1,
        "max_host_error": 3,
        "phase_timeout":  240,
    },
    "slow": {
        "timeout":        20,      # réduit par requête
        "rate_limit":     5,       # légèrement plus rapide
        "bulk_size":      10,
        "concurrency":    5,
        "retries":        1,       # 1 seul retry
        "max_host_error": 3,
        "phase_timeout":  420,     # 7 min
},
}


def _nuclei_available() -> bool:
    return shutil.which("nuclei") is not None


def _get_templates_path() -> str | None:
    for path in _TEMPLATE_PATHS:
        if path and os.path.isdir(path):
            logger.info("[Nuclei] Templates trouvés : %s", path)
            return path
    logger.error("[Nuclei] Aucun dossier de templates trouvé.")
    return None


def _filter_stderr(stderr: str) -> str:
    if not stderr:
        return ""
    real_errors = []
    for line in stderr.splitlines():
        line_stripped = line.strip()
        if not line_stripped:
            continue
        if any(token in line_stripped for token in _NUCLEI_STDERR_IGNORE):
            continue
        real_errors.append(line_stripped)
    return "\n".join(real_errors)


def _probe_target(url: str) -> dict:
    latencies = []

    for _ in range(3):
        start = time.monotonic()
        try:
            resp = requests.get(
                url,
                timeout=10,
                stream=True,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"},
            )
            resp.close()
            latencies.append(time.monotonic() - start)
        except requests.exceptions.Timeout:
            latencies.append(10.0)
        except Exception:
            try:
                req = urllib.request.Request(url, method="HEAD")
                with urllib.request.urlopen(req, timeout=10):
                    pass
                latencies.append(time.monotonic() - start)
            except Exception:
                latencies.append(10.0)

    avg = sum(latencies) / len(latencies)

    if avg < 0.5:
        profile = "fast"
    elif avg < 2.0:
        profile = "medium"
    else:
        profile = "slow"

    logger.info("[Nuclei] Probe — latence moy: %.2fs → profil: %s", avg, profile)
    return {"profile": profile, "latency": avg}


def _run_nuclei(
    url: str,
    tags: list[str],
    templates_path: str,
    profile: dict,
    phase_timeout: int,
) -> subprocess.CompletedProcess:

    cmd = [
        "nuclei",
        "-u",              url,
        "-jsonl",
        "-silent",
        "-no-color",
        "-t",              templates_path,
        "-timeout",        str(profile["timeout"]),
        "-rate-limit",     str(profile["rate_limit"]),
        "-bulk-size",      str(profile["bulk_size"]),
        "-concurrency",    str(profile["concurrency"]),
        "-severity",       ",".join(NUCLEI_SEVERITIES),
        "-tags",           ",".join(tags),
        "-disable-update-check",
        "-max-host-error", str(profile["max_host_error"]),
        "-retries",        str(profile["retries"]),
    ]

    logger.info("[Nuclei] Commande : %s", " ".join(cmd))

    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=phase_timeout,
    )


_NUCLEI_TRANSLATIONS = {
    "Weak Cipher Suites Detection": (
        "Suites de chiffrement faibles détectées",
        "Ce site utilise des algorithmes de chiffrement obsolètes. "
        "Action : désactivez RC4, DES, 3DES et activez uniquement TLS 1.2/1.3 avec AES-GCM."
    ),
    "HTTP Missing Security Headers": (
        "En-têtes de sécurité HTTP manquants",
        "Des protections importantes du navigateur sont absentes. "
        "Action : ajoutez les en-têtes de sécurité manquants dans la configuration du serveur."
    ),
    "SSL/TLS Certificate Expired": (
        "Certificat SSL/TLS expiré",
        "Le certificat SSL de ce site a expiré. "
        "Action : renouvelez immédiatement le certificat SSL."
    ),
    "SSL/TLS Certificate Self-Signed": (
        "Certificat SSL auto-signé",
        "Ce site utilise un certificat non reconnu. "
        "Action : installez un certificat signé par une autorité reconnue (ex: Let's Encrypt)."
    ),
    "TLS Version Detection": (
        "Version TLS détectée",
        "La version du protocole TLS utilisée a été identifiée."
    ),
    "Open Redirect": (
        "Redirection ouverte détectée",
        "Ce site permet des redirections vers des URLs externes non contrôlées. "
        "Action : validez et filtrez toutes les URLs de redirection."
    ),
    "Directory Listing": (
        "Listage de répertoires activé",
        "Les répertoires du serveur sont accessibles publiquement. "
        "Action : désactivez le listage de répertoires dans la configuration du serveur."
    ),
    "Exposed Git Repository": (
        "Dépôt Git exposé publiquement",
        "Le dossier .git est accessible — le code source peut être téléchargé. "
        "Action : bloquez l'accès au dossier .git via le serveur web."
    ),
    "Exposed Environment File": (
        "Fichier d'environnement exposé",
        "Le fichier .env contenant des secrets est accessible publiquement. "
        "Action : bloquez immédiatement l'accès à ce fichier."
    ),
    "PHP Info Page Exposed": (
        "Page phpinfo() exposée",
        "Des informations sensibles sur le serveur PHP sont accessibles. "
        "Action : supprimez ou protégez la page phpinfo()."
    ),
    "robots.txt Endpoint": (
        "Fichier robots.txt détecté",
        "Le fichier robots.txt révèle la structure du site. "
        "Action : vérifiez qu'aucun chemin sensible n'est listé."
    ),
    "Sitemap Detection": (
        "Sitemap détecté",
        "Le sitemap XML révèle toutes les URLs du site."
    ),
    "CORS Misconfiguration": (
        "Mauvaise configuration CORS",
        "Les politiques de partage de ressources sont mal configurées. "
        "Action : restreignez les origines autorisées dans la configuration CORS."
    ),
    "Clickjacking": (
        "Protection anti-clickjacking absente",
        "Ce site peut être intégré dans une iframe malveillante. "
        "Action : ajoutez X-Frame-Options: DENY dans les en-têtes du serveur."
    ),
    "Content Security Policy": (
        "Politique de sécurité du contenu absente",
        "Sans CSP, les attaques XSS sont plus faciles. "
        "Action : définissez une politique Content-Security-Policy stricte."
    ),
    "Subdomain Takeover": (
        "Prise de contrôle de sous-domaine possible",
        "Un sous-domaine pointe vers un service expiré. "
        "Action : supprimez ou reconfigurez ce sous-domaine immédiatement."
    ),
    "Default Login": (
        "Identifiants par défaut détectés",
        "Ce service utilise encore les identifiants par défaut. "
        "Action : changez immédiatement les mots de passe par défaut."
    ),
    "Backup File": (
        "Fichier de sauvegarde exposé",
        "Des fichiers de backup sont accessibles publiquement. "
        "Action : supprimez ou protégez ces fichiers."
    ),
    "Config File": (
        "Fichier de configuration exposé",
        "Des fichiers de configuration sensibles sont accessibles. "
        "Action : bloquez l'accès à ces fichiers via le serveur web."
    ),
    "Admin Panel": (
        "Panel d'administration exposé",
        "Une interface d'administration est accessible publiquement. "
        "Action : restreignez l'accès par IP ou ajoutez une authentification forte."
    ),
    "SQL Injection": (
        "Injection SQL possible",
        "Ce site est potentiellement vulnérable aux injections SQL. "
        "Action : utilisez des requêtes préparées et un WAF."
    ),
    "Cross-Site Scripting": (
        "Faille XSS détectée",
        "Ce site est vulnérable aux attaques Cross-Site Scripting. "
        "Action : échappez toutes les entrées utilisateur et activez CSP."
    ),
    "Waf Detection": (
        "Pare-feu applicatif détecté (WAF)",
        "Un WAF a été identifié devant ce site."
    ),
    "Laravel Debug Mode": (
        "Mode debug Laravel activé",
        "Le mode debug expose des informations sensibles. "
        "Action : définissez APP_DEBUG=false en production."
    ),
    "Nginx Version": (
        "Version Nginx exposée",
        "La version du serveur web est visible publiquement. "
        "Action : masquez la version dans la configuration Nginx."
    ),
    "WordPress": (
        "Site WordPress détecté",
        "Le CMS WordPress a été identifié."
    ),
}


def _translate_nuclei(name: str, description: str) -> tuple[str, str]:
    for key, (translated_name, translated_desc) in _NUCLEI_TRANSLATIONS.items():
        if key.lower() in name.lower():
            return translated_name, translated_desc
    return name, description


def _parse_nuclei_output(raw_lines: list[str]) -> list[dict]:
    results = []
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            name = item.get("info", {}).get("name", "")
            desc = item.get("info", {}).get("description", "")
            name_fr, desc_fr = _translate_nuclei(name, desc)
            results.append({
                "template_id": item.get("template-id", ""),
                "name":        name,
                "name_fr":     name_fr,
                "severity":    item.get("info", {}).get("severity", "info").lower(),
                "description": desc_fr,
                "matched_at":  item.get("matched-at", ""),
                "type":        item.get("type", ""),
                "tags":        item.get("info", {}).get("tags", []),
                "reference":   item.get("info", {}).get("reference", []),
                "cvss_score":  item.get("info", {}).get("classification", {}).get("cvss-score"),
                "cve_id":      item.get("info", {}).get("classification", {}).get("cve-id", []),
            })
        except json.JSONDecodeError:
            logger.debug("[Nuclei] Ligne non-JSON ignorée : %s", line[:120])
    return results


def _count_by_severity(findings: list[dict]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        if sev in counts:
            counts[sev] += 1
    return counts


def scan_nuclei(url: str) -> dict:

    if not _nuclei_available():
        return {
            "status":     "failed",
            "error":      "Nuclei n'est pas installé ou introuvable dans le PATH.",
            "error_type": "not_installed",
        }

    parsed = urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        return {
            "status":     "failed",
            "error":      "URL invalide.",
            "error_type": "invalid_url",
        }

    templates_path = _get_templates_path()
    if not templates_path:
        return {
            "status":     "failed",
            "error":      f"Templates Nuclei introuvables. Chemins testés : {_TEMPLATE_PATHS}",
            "error_type": "templates_missing",
        }

    # ── 1. Probe adaptatif ───────────────────────────────────────────────────
    probe        = _probe_target(url)
    profile_name = probe["profile"]          # "fast" | "medium" | "slow"
    profile      = PROFILES[profile_name]

    all_findings = []
    timed_out = False

    proc = None
    try:
        logger.info(
            "[Nuclei] Lancement — profil: %s — tags: %s — phase_timeout: %ds",
            profile_name, NUCLEI_TAGS_ALL, profile["phase_timeout"]
        )

        proc = _run_nuclei(
            url, NUCLEI_TAGS_ALL, templates_path,
            profile, profile["phase_timeout"]
        )

        real_errors = _filter_stderr(proc.stderr)
        if real_errors:
            logger.warning("[Nuclei] Erreurs : %s", real_errors[:500])

        logger.info("[Nuclei] Terminé — returncode: %d", proc.returncode)
        all_findings += _parse_nuclei_output(proc.stdout.splitlines())

    except subprocess.TimeoutExpired as exc:
        timed_out = True
        logger.warning(
            "[Nuclei] Timeout (%ds) — récupération des résultats partiels...",
            profile["phase_timeout"]
        )
        partial_stdout = exc.stdout or ""
        if isinstance(partial_stdout, bytes):
            partial_stdout = partial_stdout.decode(errors="ignore")
        try:
            all_findings += _parse_nuclei_output(partial_stdout.splitlines())
        except Exception:
            pass

    except Exception as exc:
        logger.exception("[Nuclei] Erreur inattendue : %s", exc)

    # ── 3. Déduplication ─────────────────────────────────────────────────
    seen, deduped = set(), []
    for f in all_findings:
        key = (f.get("template_id"), f.get("matched_at"))
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    counts = _count_by_severity(deduped)
    total  = len(deduped)

    logger.info(
        "[Nuclei] Terminé — profil=%s latence_probe=%.2fs partiel=%s — "
        "%d finding(s) : critical=%d high=%d medium=%d low=%d info=%d",
        profile_name, probe["latency"], timed_out, total,
        counts["critical"], counts["high"],
        counts["medium"], counts["low"], counts["info"],
    )

    return {
        "status":   "completed",
        "partial":  timed_out,
        "findings": deduped,
        "counts":   counts,
        "total":    total,
        "profile":  profile_name,
        "latency":  round(probe["latency"], 2),
    }