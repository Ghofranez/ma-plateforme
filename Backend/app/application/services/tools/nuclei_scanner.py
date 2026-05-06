"""
nuclei_scanner.py — Scan de vulnérabilités avec Nuclei (version robuste)
"""

import subprocess
import json
import logging
import shutil
import os
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Timeout global pour le scan Nuclei (en secondes)
NUCLEI_TIMEOUT = 300

# Templates path avec fallback automatique
_TEMPLATE_PATHS = [
    "/home/celeryuser/nuclei-templates/",
    os.path.expanduser("~/nuclei-templates/"),
    "/root/nuclei-templates/",
]

# Tags légers — toujours exécutés (rapides, ~30s)
NUCLEI_TAGS_FAST = [
    "misconfig",   # mauvaises configurations
    "exposure",    # fichiers/données exposés
    "takeover",    # prise de contrôle sous-domaine
]

# Tags profonds — best-effort (plus lents, ~90s)
NUCLEI_TAGS_DEEP = [
    "xss",         # Cross-Site Scripting
    "sqli",        # SQL Injection
    "lfi",         # Local File Inclusion
    "rce",         # Remote Code Execution
    "ssrf",        # Server-Side Request Forgery
    "cve",         # CVEs connus
]

# Severities à remonter
NUCLEI_SEVERITIES = ["critical", "high", "medium", "low", "info"]


def _nuclei_available() -> bool:
    return shutil.which("nuclei") is not None


def _get_templates_path() -> str | None:
    """Retourne le premier path de templates valide trouvé."""
    for path in _TEMPLATE_PATHS:
        if os.path.isdir(path):
            logger.info("[Nuclei] Templates trouvés : %s", path)
            return path
    logger.error("[Nuclei] Aucun dossier de templates trouvé. Chemins testés : %s", _TEMPLATE_PATHS)
    return None


def _run_nuclei(url: str, tags: list[str], templates_path: str) -> subprocess.CompletedProcess:
    """Lance une commande Nuclei et retourne le résultat."""
    cmd = [
        "nuclei",
        "-u",           url,
        "-jsonl",
        "-silent",
        "-no-color",
        "-t",           templates_path,
        "-timeout",     "10",
        "-rate-limit",  "15",
        "-bulk-size",   "10",
        "-concurrency", "5",
        "-severity",    ",".join(NUCLEI_SEVERITIES),
        "-tags",        ",".join(tags),
        "-disable-update-check",
        "-max-host-error", "5",
        "-retries",     "1",  # 1 retry pour éviter les faux silences réseau
    ]

    logger.info("[Nuclei] Commande : %s", " ".join(cmd))

    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=NUCLEI_TIMEOUT,
    )


def _parse_nuclei_output(raw_lines: list[str]) -> list[dict]:
    """
    Nuclei sort du JSONL (1 JSON par ligne).
    """
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
    """
    Lance Nuclei sur l'URL cible et retourne un rapport normalisé.
    """

    # ── 1. Vérifications préalables ──────────────────────────────────────────
    if not _nuclei_available():
        logger.error("[Nuclei] Binaire introuvable dans le PATH")
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

    # ── 2. Phase FAST ────────────────────────────────────────────────────────
    all_findings = []

    try:
        logger.info("[Nuclei] Phase 1 (fast) — tags : %s", NUCLEI_TAGS_FAST)
        proc_fast = _run_nuclei(url, NUCLEI_TAGS_FAST, templates_path)

        if proc_fast.stderr:
            logger.info("[Nuclei] stderr phase1 : %s", proc_fast.stderr[:1000])

        logger.info("[Nuclei] returncode phase1 : %d", proc_fast.returncode)
        logger.info("[Nuclei] stdout phase1 (%d lignes) : %s",
                    len(proc_fast.stdout.splitlines()),
                    proc_fast.stdout[:500] if proc_fast.stdout else "(vide)")

        all_findings += _parse_nuclei_output(proc_fast.stdout.splitlines())

    except subprocess.TimeoutExpired:
        logger.warning("[Nuclei] Timeout phase 1 — résultats partiels conservés")

    except Exception as exc:
        logger.exception("[Nuclei] Erreur inattendue phase 1 : %s", exc)

    # ── 3. Phase DEEP (best-effort) ──────────────────────────────────────────
    try:
        logger.info("[Nuclei] Phase 2 (deep) — tags : %s", NUCLEI_TAGS_DEEP)
        proc_deep = _run_nuclei(url, NUCLEI_TAGS_DEEP, templates_path)

        if proc_deep.stderr:
            logger.info("[Nuclei] stderr phase2 : %s", proc_deep.stderr[:1000])

        logger.info("[Nuclei] returncode phase2 : %d", proc_deep.returncode)
        logger.info("[Nuclei] stdout phase2 (%d lignes) : %s",
                    len(proc_deep.stdout.splitlines()),
                    proc_deep.stdout[:500] if proc_deep.stdout else "(vide)")

        all_findings += _parse_nuclei_output(proc_deep.stdout.splitlines())

    except subprocess.TimeoutExpired:
        logger.warning("[Nuclei] Timeout phase 2 — résultats phase 1 conservés")

    except Exception as exc:
        logger.exception("[Nuclei] Erreur inattendue phase 2 : %s", exc)

    # ── 4. Déduplication (même template_id + matched_at) ────────────────────
    seen = set()
    deduped = []
    for f in all_findings:
        key = (f.get("template_id"), f.get("matched_at"))
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    counts = _count_by_severity(deduped)
    total  = len(deduped)

    logger.info(
        "[Nuclei] Terminé — %d finding(s) : critical=%d high=%d medium=%d low=%d info=%d",
        total, counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"]
    )

    return {
        "status":   "completed",
        "findings": deduped,
        "counts":   counts,
        "total":    total,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Traductions Nuclei
# ─────────────────────────────────────────────────────────────────────────────

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
    """Traduit le nom et la description d'un finding Nuclei en français."""
    for key, (translated_name, translated_desc) in _NUCLEI_TRANSLATIONS.items():
        if key.lower() in name.lower():
            return translated_name, translated_desc
    return name, description