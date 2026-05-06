"""
zap_scanner.py — Scanner OWASP ZAP via API REST
Mode : spider léger + scan passif (safe, lecture seule)
"""

import os
import time
import requests
from urllib.parse import urlparse
from deep_translator import GoogleTranslator
ZAP_BASE_URL = os.getenv("ZAP_BASE_URL", "http://zap:8090")
ZAP_API_KEY  = os.getenv("ZAP_API_KEY",  "")

SPIDER_TIMEOUT_S  = 120
PASSIVE_TIMEOUT_S = 120
POLL_INTERVAL_S   = 5

# Alertes redondantes avec vos autres scanners — ignorées pour éviter les doublons
_IGNORED_ALERTS = {
    "Re-examine Cache-control Directives",
    "X-Content-Type-Options Header Missing",
    "Anti-clickjacking Header",
    "Content Security Policy (CSP) Header Not Set",
    "Missing Anti-clickjacking Header",
    "Strict-Transport-Security Header Not Set",
    "Server Leaks Information via 'X-Powered-By' HTTP Response Header Field(s)",
}

# ─────────────────────────────────────────────────────────────────────────────
# Dictionnaire de traduction ZAP (anglais → français)
# ─────────────────────────────────────────────────────────────────────────────
_ZAP_TRANSLATIONS = {

    # ── Noms d'alertes ──────────────────────────────────────────────────────
    "SQL Injection":
        "Injection SQL",
    "SQL Injection - MySQL":
        "Injection SQL — MySQL",
    "SQL Injection - SQLite":
        "Injection SQL — SQLite",
    "SQL Injection - PostgreSQL":
        "Injection SQL — PostgreSQL",
    "SQL Injection - MsSQL":
        "Injection SQL — Microsoft SQL Server",
    "Blind SQL Injection":
        "Injection SQL aveugle",
    "Cross Site Scripting (Reflected)":
        "Script inter-sites XSS (réfléchi)",
    "Cross Site Scripting (Persistent)":
        "Script inter-sites XSS (persistant)",
    "Cross Site Scripting (DOM Based)":
        "Script inter-sites XSS (basé sur le DOM)",
    "Cross Site Scripting (Persistent) - Prime":
        "Script inter-sites XSS persistant (principal)",
    "Cross Site Scripting (Persistent) - Spider":
        "Script inter-sites XSS persistant (spider)",
    "Path Traversal":
        "Traversée de répertoire",
    "Remote File Inclusion":
        "Inclusion de fichier distant",
    "Command Injection":
        "Injection de commande système",
    "Server Side Request Forgery":
        "Falsification de requête côté serveur (SSRF)",
    "Server Side Template Injection":
        "Injection de template côté serveur (SSTI)",
    "Remote Code Execution - CVE-2012-1823":
        "Exécution de code distant — CVE-2012-1823",
    "XML External Entity Attack":
        "Attaque par entité externe XML (XXE)",
    "XSLT Injection":
        "Injection XSLT",
    "XPath Injection":
        "Injection XPath",
    "LDAP Injection":
        "Injection LDAP",
    "Log4Shell":
        "Faille Log4Shell (Log4j)",

    "CSRF":
        "Falsification de requête inter-sites (CSRF)",
    "Absence of Anti-CSRF Tokens":
        "Absence de tokens anti-CSRF",
    "Missing Anti-CSRF Tokens":
        "Tokens anti-CSRF manquants",

    "Vulnerable JS Library":
        "Bibliothèque JavaScript vulnérable",
    "Vulnerable JS Library (Powered by Retire.js)":
        "Bibliothèque JavaScript vulnérable (Retire.js)",

    "Cookie Without Secure Flag":
        "Cookie sans attribut Secure",
    "Cookie Without SameSite Attribute":
        "Cookie sans attribut SameSite",
    "Cookie No HttpOnly Flag":
        "Cookie sans attribut HttpOnly",
    "Loosely Scoped Cookie":
        "Cookie avec portée de domaine trop large",
    "Cookie Poisoning":
        "Empoisonnement de cookie",
    "Session ID in URL Rewrite":
        "Identifiant de session exposé dans l'URL",

    "Application Error Disclosure":
        "Divulgation d'erreur applicative",
    "Directory Browsing":
        "Navigation dans les répertoires activée",
    "Private IP Disclosure":
        "Divulgation d'adresse IP privée",
    "Information Disclosure - Debug Error Messages":
        "Divulgation d'informations — Messages d'erreur de débogage",
    "Information Disclosure - Sensitive Information in URL":
        "Divulgation d'informations sensibles dans l'URL",
    "Information Disclosure - Sensitive Information in HTTP Referrer Header":
        "Divulgation d'informations sensibles via l'en-tête Referrer",
    "Information Disclosure - Suspicious Comments":
        "Divulgation d'informations — Commentaires suspects dans le code",
    "Hash Disclosure":
        "Divulgation de hash",
    "Timestamp Disclosure - Unix":
        "Divulgation d'horodatage Unix",
    "Timestamp Disclosure":
        "Divulgation d'horodatage",
    "Username Hash Found":
        "Hash de nom d'utilisateur détecté",

    'Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)':
        "Fuite d'information via l'en-tête X-Powered-By",
    "Server Leaks Version Information via Server HTTP Response Header Field":
        "Fuite de version via l'en-tête Server HTTP",
    "X-Backend-Server Header Information Leak":
        "Fuite d'information via l'en-tête X-Backend-Server",
    "HTTP Server Response Header":
        "En-tête de réponse du serveur HTTP exposé",
    "In Page Banner Information Leak":
        "Fuite d'information via bannière dans la page",

    "Content Security Policy (CSP) Header Not Set":
        "En-tête Content Security Policy (CSP) absent",
    "CSP":
        "Problème de politique de sécurité du contenu (CSP)",
    "X-Content-Type-Options Header Missing":
        "En-tête X-Content-Type-Options absent",
    "Anti-clickjacking Header":
        "En-tête anti-clickjacking absent",
    "Strict-Transport-Security Header":
        "En-tête HSTS (Strict-Transport-Security) absent",
    "Strict-Transport-Security Header Not Set":
        "En-tête HSTS non défini",
    "Re-examine Cache-control Directives":
        "Directives Cache-Control à revoir",
    "Content-Type Header Missing":
        "En-tête Content-Type absent",
    "Sub Resource Integrity Attribute Missing":
        "Attribut d'intégrité des sous-ressources (SRI) manquant",
    "Permissions Policy Header Not Set":
        "En-tête Permissions-Policy absent",

    "Cross-Domain JavaScript Source File Inclusion":
        "Inclusion de fichier JavaScript depuis un domaine externe",
    "Cross-Domain Misconfiguration":
        "Mauvaise configuration inter-domaines (CORS)",
    "Insecure Direct Object Reference":
        "Référence directe à un objet non sécurisée (IDOR)",
    "Insecure JSF ViewState":
        "ViewState JSF non sécurisé",
    "Java Serialization Object":
        "Objet de sérialisation Java détecté",
    "Heartbleed OpenSSL Vulnerability":
        "Vulnérabilité Heartbleed (OpenSSL)",
    "Reverse Tabnabbing":
        "Attaque Reverse Tabnabbing",
    "Secure Pages Include Mixed Content":
        "Page sécurisée incluant du contenu mixte (HTTP/HTTPS)",
    "HTTP to HTTPS Insecure Transition in Form Post":
        "Transition non sécurisée HTTP→HTTPS dans un formulaire",
    "HTTPS to HTTP Insecure Transition in Form Post":
        "Transition non sécurisée HTTPS→HTTP dans un formulaire",
    "Weak Authentication Method":
        "Méthode d'authentification faible",
    "Absence of Anti-CSRF Tokens":
        "Absence de protection anti-CSRF",
    "PII Disclosure":
        "Divulgation d'informations personnelles identifiables (PII)",
    "Modern Web Application":
        "Application web moderne détectée",
    "Retrieved from Cache":
        "Ressource récupérée depuis le cache",
    "Big Redirect Detected (Potential Sensitive Information Leak)":
        "Redirection volumineuse détectée — fuite d'information potentielle",
    "Script Served From Malicious Domain (polyfill)":
        "Script chargé depuis un domaine malveillant (polyfill)",
    "User Controllable HTML Element Attribute (Potential XSS)":
        "Attribut HTML contrôlable par l'utilisateur (XSS potentiel)",
    "User Controllable JavaScript Event (XSS)":
        "Événement JavaScript contrôlable par l'utilisateur (XSS)",
    "User Controllable Charset":
        "Jeu de caractères contrôlable par l'utilisateur",
    "Off-site Redirect":
        "Redirection vers un site externe",
    "Viewstate":
        "ViewState exposé",
    "X-AspNet-Version Response Header":
        "En-tête X-AspNet-Version exposé",
    "X-ChromeLogger-Data (XCOLD) Header Information Leak":
        "Fuite d'information via l'en-tête X-ChromeLogger-Data",
    "X-Debug-Token Information Leak":
        "Fuite d'information via X-Debug-Token",
    "WSDL File Detection":
        "Fichier WSDL détecté (exposition de l'API)",
    "Charset Mismatch":
        "Incohérence de jeu de caractères",
    "ZAP is Out of Date":
        "Version de ZAP obsolète",
    "Ensure that your web server, application server, load balancer, etc. is configured to suppress the \"Server\" header or provide generic details.":
    "Configurez votre serveur pour masquer ou généraliser l'en-tête Server (ex: ServerTokens Prod sur Apache).",

    "Whenever a cookie contains sensitive information or is a session token, then it should always be passed using an encrypted channel. Ensure that the secure flag is set for cookies containing such sensitive information.":
    "Ajoutez l'attribut Secure à tous les cookies sensibles pour les limiter aux connexions HTTPS uniquement.",

    "Ensure that the HttpOnly flag is set for all cookies.":
    "Ajoutez l'attribut HttpOnly à tous vos cookies de session pour les rendre inaccessibles via JavaScript.",

    # ── Solutions ────────────────────────────────────────────────────────────
    "Provide a valid integrity attribute to the tag.":
        "Ajoutez un attribut integrity valide à chaque balise <script> et <link> externe.",
    "Ensure JavaScript source files are loaded from only trusted sources, and the sources can't be controlled by end users of the application.":
        "Chargez les fichiers JavaScript uniquement depuis des sources de confiance non modifiables par les utilisateurs.",
    'Ensure that your web server, application server, load balancer, etc. is configured to suppress "X-Powered-By" headers.':
        "Configurez votre serveur pour supprimer les en-têtes X-Powered-By (ServerTokens Prod sur Apache, plus_set_headers sur Nginx).",
    "Ensure that no sensitive information is leaked via redirect responses. Redirect responses should have almost no content.":
        "Vérifiez que les réponses de redirection ne contiennent aucune information sensible et ont un contenu minimal.",
    "Ensure that your web server, application server, load balancer, etc. is configured to set the Strict-Transport-Security header.":
        "Configurez votre serveur pour envoyer l'en-tête Strict-Transport-Security (HSTS).",
    "Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.":
        "Configurez votre serveur pour envoyer l'en-tête Content-Security-Policy.",
    "Ensure that your web server, application server, load balancer, etc. is configured to set the X-Content-Type-Options header.":
        "Configurez votre serveur pour envoyer l'en-tête X-Content-Type-Options: nosniff.",
    "Use HttpOnly flag when setting a cookie.":
        "Ajoutez l'attribut HttpOnly à tous vos cookies de session.",
    "Ensure that the SameSite attribute is set to either 'lax' or ideally 'strict' for all cookies.":
        "Définissez l'attribut SameSite=Strict ou SameSite=Lax sur tous vos cookies.",
    "Ensure that the Secure flag is set for cookies.":
        "Ajoutez l'attribut Secure à tous vos cookies pour les limiter aux connexions HTTPS.",
    "Do not use GET requests to submit sensitive information. Use POST requests instead.":
        "N'utilisez pas de requêtes GET pour soumettre des informations sensibles. Utilisez POST à la place.",
    "Validate all input and sanitize output it before writing to any HTML attributes.":
        "Validez toutes les entrées et échappez les sorties avant de les insérer dans des attributs HTML.",
    "Phase: Architecture and Design\nUse a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.":
        "Utilisez une bibliothèque ou un framework éprouvé qui évite cette vulnérabilité ou facilite sa prévention.",
    "Disable directory browsing. If this is required, make sure the listed files does not induce risks.":
        "Désactivez la navigation dans les répertoires. Si nécessaire, assurez-vous que les fichiers listés ne présentent aucun risque.",
    "Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.":
        "Vérifiez manuellement que les données d'horodatage ne sont pas sensibles et ne peuvent pas être agrégées pour révéler des schémas exploitables.",
    "Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.":
        "Supprimez tous les commentaires contenant des informations utiles à un attaquant et corrigez les problèmes sous-jacents.",
    "Upgrade to the latest version of the affected library.":
    "Mettez à jour la bibliothèque JavaScript concernée vers sa dernière version.",
}

_ZAP_ALERT_EXPLANATIONS = {
    "Sub Resource Integrity Attribute Missing": (
        "Des ressources externes ne sont pas vérifiées — elles pourraient être modifiées par un attaquant. "
        "Action : ajoutez l'attribut integrity à chaque script et style externe."
    ),
    "Cookie No HttpOnly Flag": (
        "Vos cookies sont accessibles aux scripts malveillants. "
        "Action : ajoutez HttpOnly à vos cookies de session."
    ),
    "Cross-Domain JavaScript Source File Inclusion": (
        "Votre site charge des scripts depuis des sites externes non vérifiés. "
        "Action : hébergez ces scripts sur votre serveur ou ajoutez l'attribut integrity."
    ),
    'Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)': (
        "Votre serveur révèle sa technologie aux attaquants. "
        "Action : supprimez l'en-tête X-Powered-By dans la configuration serveur."
    ),
    "Big Redirect Detected (Potential Sensitive Information Leak)": (
        "Vos redirections contiennent trop de données — risque de fuite. "
        "Action : vérifiez que vos redirections ne transmettent aucune donnée sensible."
    ),
    "SQL Injection": (
        "Un attaquant peut lire ou modifier votre base de données. "
        "Action : utilisez des requêtes préparées, jamais de données utilisateur dans le SQL."
    ),
    "Cross Site Scripting (Reflected)": (
        "Du code malveillant peut s'exécuter via un lien piégé. "
        "Action : échappez toutes les données affichées et activez Content-Security-Policy."
    ),
    "Cross Site Scripting (Persistent)": (
        "Du code malveillant est stocké et s'exécute chez tous vos visiteurs. "
        "Action : validez et échappez toutes les données avant stockage et affichage."
    ),
    "Cross Site Scripting (DOM Based)": (
        "Du code malveillant peut être injecté via le navigateur. "
        "Action : évitez innerHTML avec des données non fiables, utilisez textContent."
    ),
    "Path Traversal": (
        "Un attaquant peut accéder à des fichiers privés du serveur. "
        "Action : validez tous les chemins de fichiers côté serveur."
    ),
    "Remote File Inclusion": (
        "Un attaquant peut exécuter du code depuis un serveur distant. "
        "Action : désactivez allow_url_include et ne construisez pas de chemins depuis les entrées utilisateur."
    ),
    "Command Injection": (
        "Un attaquant peut exécuter des commandes sur votre serveur. "
        "Action : n'utilisez jamais les entrées utilisateur dans des commandes système."
    ),
    "Directory Browsing": (
        "La liste de vos fichiers est visible publiquement. "
        "Action : désactivez l'indexation des répertoires sur votre serveur."
    ),
    "Application Error Disclosure": (
        "Des erreurs techniques sont affichées aux visiteurs. "
        "Action : désactivez les erreurs en production et redirigez-les vers des logs privés."
    ),
    "Private IP Disclosure": (
        "Des adresses IP internes sont exposées dans vos réponses. "
        "Action : supprimez toute référence à des IPs privées dans vos réponses."
    ),
    "Vulnerable JS Library": (
        "Une bibliothèque JavaScript vulnérable est utilisée sur ce site. "
        "Action : mettez à jour vos dépendances JavaScript."
    ),
    "Cookie Without Secure Flag": (
        "Vos cookies peuvent être interceptés sur un réseau non sécurisé. "
        "Action : ajoutez l'attribut Secure à vos cookies."
    ),
    "Cookie Without SameSite Attribute": (
        "Vos cookies sont envoyés depuis n'importe quel site — risque CSRF. "
        "Action : ajoutez SameSite=Strict à vos cookies de session."
    ),
    "Absence of Anti-CSRF Tokens": (
        "Vos formulaires peuvent être soumis par un site malveillant à votre place. "
        "Action : ajoutez un token CSRF unique sur chaque formulaire."
    ),
    "CSRF": (
        "Vos formulaires peuvent être soumis par un site malveillant à votre place. "
        "Action : ajoutez un token CSRF unique sur chaque formulaire."
    ),
    "Information Disclosure - Suspicious Comments": (
        "Des commentaires dans votre code contiennent des informations sensibles. "
        "Action : supprimez tous les commentaires sensibles avant la mise en production."
    ),
    "Information Disclosure - Debug Error Messages": (
        "Des messages de débogage sont visibles par les visiteurs. "
        "Action : désactivez le mode debug en production."
    ),
    "Timestamp Disclosure": (
        "Des horodatages du serveur sont exposés dans vos réponses. "
        "Action : masquez les horodatages inutiles."
    ),
    "Loosely Scoped Cookie": (
        "Vos cookies sont accessibles à tous vos sous-domaines. "
        "Action : définissez un domaine précis pour chaque cookie."
    ),
    "Hash Disclosure": (
        "Des valeurs hashées sensibles sont exposées dans vos réponses. "
        "Action : ne renvoyez jamais de hash au client."
    ),
    "Session ID in URL Rewrite": (
        "L'identifiant de session est visible dans l'URL. "
        "Action : stockez les sessions uniquement dans des cookies sécurisés."
    ),
    "Cross-Domain Misconfiguration": (
        "Votre configuration CORS est trop permissive. "
        "Action : limitez Access-Control-Allow-Origin aux domaines de confiance."
    ),
    "Reverse Tabnabbing": (
        "Vos liens externes peuvent rediriger votre page vers un site malveillant. "
        "Action : ajoutez rel='noopener noreferrer' à tous vos liens externes."
    ),
    "Server Side Request Forgery": (
        "Un attaquant peut forcer votre serveur à contacter des ressources internes. "
        "Action : validez strictement toutes les URLs fournies par les utilisateurs."
    ),
    "XML External Entity Attack": (
        "Votre parseur XML accepte des entités externes dangereuses. "
        "Action : désactivez le traitement des entités externes dans votre parseur XML."
    ),
    "Weak Authentication Method": (
        "Votre méthode d'authentification est trop faible. "
        "Action : utilisez uniquement des méthodes d'authentification sécurisées sur HTTPS."
    ),
    "Insecure Direct Object Reference": (
        "Des ressources privées sont accessibles en devinant leur identifiant. "
        "Action : vérifiez les droits d'accès côté serveur pour chaque ressource."
    ),
    "Server Leaks Version Information": (
        "Votre serveur affiche sa version publiquement. "
        "Action : masquez la version dans la configuration serveur."
    ),
    "Content Security Policy (CSP) Header Not Set": (
        "Votre site n'a pas de politique de sécurité du contenu. "
        "Action : définissez un en-tête Content-Security-Policy sur votre serveur."
    ),
}

_translation_cache = {}

def _translate(text: str) -> str:
    if not text:
        return text
    # 1. Dictionnaire manuel (priorité)
    if text in _ZAP_TRANSLATIONS:
        return _ZAP_TRANSLATIONS[text]
    # 2. Traduction automatique avec cache
    if text in _translation_cache:
        return _translation_cache[text]
    try:
        translated = GoogleTranslator(source="en", target="fr").translate(text[:500])
        _translation_cache[text] = translated
        return translated
    except Exception:
        return text


def _zap_get(path: str, params: dict = None) -> dict:
    base_params = {"apikey": ZAP_API_KEY, "zapapiformat": "JSON"}
    if params:
        base_params.update(params)
    resp = requests.get(
        f"{ZAP_BASE_URL}{path}",
        params=base_params,
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def _wait_for_spider(scan_id: str) -> bool:
    elapsed = 0
    while elapsed < SPIDER_TIMEOUT_S:
        data     = _zap_get("/JSON/spider/view/status/", {"scanId": scan_id})
        progress = int(data.get("status", 0))
        if progress >= 100:
            return True
        time.sleep(POLL_INTERVAL_S)
        elapsed += POLL_INTERVAL_S
    return False


def _wait_for_passive_scan() -> bool:
    """Attend max PASSIVE_TIMEOUT_S que ZAP finisse le scan passif.
    Retourne True si terminé, False si timeout — dans les deux cas on continue."""
    elapsed = 0
    while elapsed < PASSIVE_TIMEOUT_S:
        try:
            data      = _zap_get("/JSON/pscan/view/recordsToScan/")
            remaining = int(data.get("recordsToScan", 0))
            if remaining == 0:
                return True
        except Exception:
            return False
        time.sleep(POLL_INTERVAL_S)
        elapsed += POLL_INTERVAL_S
    return False  #


def _parse_alerts(alerts: list) -> dict:
    by_risk    = {"High": [], "Medium": [], "Low": [], "Informational": []}
    seen_names = set()

    for alert in alerts:
        name = alert.get("name", "")
        risk = alert.get("risk", "Informational")

        if name in _IGNORED_ALERTS or name in seen_names:
            continue
        seen_names.add(name)

        by_risk.setdefault(risk, []).append({
            "name":        _translate(name),
            "name_original": name,
            "risk":        risk,
            "description": _translate(alert.get("description", ""))[:300],
            "solution":    _translate(alert.get("solution",    ""))[:300],
            "solution_original": alert.get("solution", "")[:300],
            "cweid":       alert.get("cweid", ""),
            "wascid":      alert.get("wascid", ""),
        })

    total = sum(len(v) for v in by_risk.values())
    return {
        "by_risk": by_risk,
        "total":   total,
        "counts": {
            "high":   len(by_risk["High"]),
            "medium": len(by_risk["Medium"]),
            "low":    len(by_risk["Low"]),
            "info":   len(by_risk["Informational"]),
        },
    }


def run_zap_scan(url: str) -> dict:
    """Point d'entrée — appelé depuis scanner.py"""
    try:
        # ── 0. Vérifier que ZAP est accessible ──
        try:
            _zap_get("/JSON/core/view/version/")
        except requests.exceptions.ConnectionError:
            return {
                "status":     "failed",
                "error":      "ZAP non accessible — conteneur non démarré.",
                "error_type": "connection_error",
            }

        # ── 1. Nettoyer les alertes précédentes ──
        try:
            _zap_get("/JSON/core/action/deleteAllAlerts/")
        except Exception:
            pass

         # ──  désactiver la règle "Suspicious Comments" qui bloque sur les gros JS ──
        try:
            _zap_get("/JSON/pscan/action/disableScanners/", {"ids": "10027"})
        except Exception:
            pass

        # ── 2. Spider (crawl léger, max 5 sous-pages) ──
        spider_resp = _zap_get(
            "/JSON/spider/action/scan/",
            {"url": url, "maxChildren": "5", "recurse": "true"},
        )
        scan_id = spider_resp.get("scan")
        if not scan_id:
            return {
                "status":     "failed",
                "error":      "Le spider ZAP n'a pas démarré.",
                "error_type": "spider_failed",
            }

        # ──  exclure les fichiers médias/binaires volumineux ──
        try:
            _zap_get("/JSON/spider/action/excludeFromScan/", {
                "regex": r".*\.(mp4|mp3|avi|mkv|mov|wmv|flv|iso|zip|tar|gz|exe|dmg|pdf|jpg|jpeg|png|gif|svg|woff|woff2|ttf)(\?.*)?$"
            })
        except Exception:
            pass

        spider_ok = _wait_for_spider(scan_id)

        # ── 3. Attendre fin du scan passif ──
        _wait_for_passive_scan()

        # ── 4. Récupérer les alertes ──
        alerts_resp = _zap_get(
            "/JSON/core/view/alerts/",
            {"baseurl": url, "start": "0", "count": "200"},
        )
        raw_alerts = alerts_resp.get("alerts", [])
        parsed     = _parse_alerts(raw_alerts)

        return {
            "status":           "completed",
            "url":              url,
            "domain":           urlparse(url).netloc or url,
            "alerts":           parsed,
            "spider_completed": spider_ok,
        }

    except requests.exceptions.Timeout:
        return {
            "status":     "failed",
            "error":      "timeout",
            "error_type": "timeout",
        }
    except Exception as e:
        return {
            "status":     "failed",
            "error":      str(e)[:200],
            "error_type": "exception",
        }