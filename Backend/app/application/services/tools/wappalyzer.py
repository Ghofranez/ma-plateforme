"""
wappalyzer.py — Scanner de fingerprinting technologique

"""

import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ==============================================================================
# TABLE DES TECHNOLOGIES À RISQUE CONNU
# ==============================================================================

_RISKY_TECHNOLOGIES: dict[str, str] = {
    # CMS — cibles privilégiées car très répandus et souvent mal mis à jour
    "wordpress":        "high",    # Le CMS le plus attaqué au monde
    "drupal":           "high",    # "Drupalgeddon" — failles RCE critiques
    "joomla":           "high",    # Attaques automatisées fréquentes
    "magento":          "high",    # Cible de skimming (vol de CB)

    # E-commerce
    "opencart":         "medium",
    "prestashop":       "medium",
    "woocommerce":      "medium",  # Plugin WordPress — hérite de ses risques

    # Frameworks backend
    "laravel":          "medium",  # Failles connues sur anciennes versions
    "apache struts":    "high",    # Faille Equifax 2017 (CVE-2017-5638)
    "spring":           "medium",  # Spring4Shell (CVE-2022-22965)
    "django":           "low",     # Bon historique de sécurité
    "ruby on rails":    "medium",

    # Serveurs web
    "apache":           "medium",  # Vulnérabilités fréquentes selon la version
    "nginx":            "low",     # Bon historique, mais version exposée = info utile
    "iis":              "medium",  # Microsoft IIS, cible Windows
    "apache tomcat":    "high",    # CVEs critiques permettant RCE
    "jetty":            "medium",

    # Langages côté serveur (la version visible = surface d'attaque)
    "php":              "medium",  # Versions < 8.1 sans support actif
    "asp.net":          "medium",

    # Interfaces d'administration exposées — risque maximal si publiques
    "phpmyadmin":       "high",    # BD MySQL accessible depuis Internet = critique
    "webmin":           "high",    # Administration système exposée
    "cpanel":           "medium",
    "plesk":            "medium",

    # Bibliothèques JavaScript
    "jquery":           "medium",  # Versions < 3.5 : XSS connus
    "angularjs":        "medium",  # End-of-life depuis déc. 2021 (plus de patches)

    # CDN / Infrastructure (risque faible, info utile)
    "cloudflare":       "low",
    "amazon cloudfront":"low",
    "shopify":          "low",     # SaaS managé, peu de risque côté sécurité
    "bootstrap":        "low",
}


# Catégories Wappalyzer/builtwith considérées comme sensibles.
_SENSITIVE_CATEGORIES = {
    "cms",                  # Systèmes de gestion de contenu
    "ecommerce",            # Boutiques en ligne (données bancaires)
    "web-servers",          # Serveurs web (version exposée = info d'attaque)
    "programming-languages",# Langage backend visible → version ciblable
    "database-managers",    # Interfaces de gestion de BD (phpMyAdmin…)
    "admin",                # Outils d'administration exposés
    "web-frameworks",       # Frameworks : failles selon version
}


# ==============================================================================
# FONCTIONS UTILITAIRES INTERNES
# ==============================================================================

def _normalize(name: str) -> str:
    """
    Normalise un nom de technologie pour la comparaison.
    Ex: "  WordPress  " → "wordpress"
    On utilise strip() + lower() pour éviter les faux négatifs dus à la casse.
    """
    return name.strip().lower()


def _assess_risk(tech_name: str, category: str = "") -> str:
    """
    Détermine le niveau de risque d'une technologie selon 3 règles (par priorité) :
      1. Correspondance exacte dans _RISKY_TECHNOLOGIES
      2. Correspondance partielle (ex: "apache tomcat 9.0" contient "apache tomcat")
      3. Catégorie sensible → risque medium par défaut
      4. Sinon → low
    """
    normalized = _normalize(tech_name)

    # Règle 1 : correspondance exacte (la plus fiable)
    if normalized in _RISKY_TECHNOLOGIES:
        return _RISKY_TECHNOLOGIES[normalized]

    # Règle 2 : correspondance partielle (gère les noms avec version intégrée)
    # Ex: "WordPress 6.2" → contient "wordpress" → high
    for key, level in _RISKY_TECHNOLOGIES.items():
        if key in normalized:
            return level

    # Règle 3 : catégorie sensible même si la techno n'est pas listée
    if category.lower() in _SENSITIVE_CATEGORIES:
        return "medium"

    # Règle 4 : risque minimal par défaut
    return "low"


def _compute_risk_level(technologies: list[dict]) -> str:
    """
    Calcule le niveau de risque global de la stack détectée.

    """
    if any(t["risk"] == "high"   for t in technologies):
        return "high"
    if any(t["risk"] == "medium" for t in technologies):
        return "medium"
    return "low"


def _failure(error: str) -> dict:
    """
    Retourne un résultat d'échec standardisé.

    """
    return {
        "status":            "failed",
        "error":             error,
        "technologies":      [],
        "risk_technologies": [],
        "risk_level":        "low",
    }


# ==============================================================================
# FONCTION PRINCIPALE
# ==============================================================================

def scan_wappalyzer(url: str) -> dict:
    """
    Analyse la stack technologique d'un site web via builtwith.

    """

    # ── Étape 1 : Validation de l'URL ─────────────────────────────────────────
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return _failure(f"URL invalide (scheme ou domaine manquant) : {url}")
    except Exception as e:
        return _failure(f"Erreur de parsing URL : {e}")

    # ── Étape 2 : Import de builtwith ─────────────────────────────────────────
    try:
        import builtwith
    except ImportError:
        return _failure(
            "builtwith n'est pas installé. "
            "Ajoutez 'builtwith' dans requirements.txt et relancez pip install."
        )

    logger.info(f"[Wappalyzer/builtwith] Analyse de : {url}")

    # ── Étape 3 : Analyse builtwith ───────────────────────────────────────────
    try:
        raw: dict = builtwith.parse(url)
    except Exception as e:
        # Peut échouer si le site est hors ligne, protégé par Cloudflare, timeout…
        logger.warning(f"[Wappalyzer/builtwith] Échec de l'analyse pour {url} : {e}")
        return _failure(f"Erreur lors de l'analyse du site : {str(e)[:300]}")

    # ── Étape 4 : Construction de la liste normalisée ─────────────────────────
    technologies: list[dict] = []

    for category, tech_list in raw.items():
        for tech_name in tech_list:
            risk = _assess_risk(tech_name, category)
            technologies.append({
                "name":       tech_name,
                "version":    "",
                "categories": [category],
                "confidence": 100,
                "cpe":        "",
                "risk":       risk,
            })

    # ── Étape 5 : Tri des résultats ───────────────────────────────────────────
    technologies.sort(key=lambda t: (
        0 if t["risk"] == "high" else 1 if t["risk"] == "medium" else 2,
        t["name"].lower(),
    ))

    # ── Étape 6 : Calcul du niveau de risque global ───────────────────────────
    risk_techs = [t for t in technologies if t["risk"] != "low"]
    risk_level  = _compute_risk_level(technologies)

    logger.info(
        f"[Wappalyzer/builtwith] Résultat pour {url} : "
        f"{len(technologies)} techno(s) détectée(s), "
        f"{len(risk_techs)} à risque, "
        f"niveau global : {risk_level}"
    )

    return {
        "status":            "completed",
        "technologies":      technologies,
        "risk_technologies": risk_techs,
        "risk_level":        risk_level,
    }