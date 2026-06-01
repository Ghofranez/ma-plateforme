from datetime import datetime
from app.application.services.celery_app            import celery_app
from app.infrastructure.db.session                  import SessionLocal
from app.infrastructure.repositories.analysis_repo  import AnalysisRepository
from app.application.services.tools.security_headers import scan_headers
from app.application.services.tools.ssl_labs         import scan_ssl
from app.application.services.tools.testssl          import scan_testssl
from app.application.services.tools.virustotal       import scan_virustotal
from app.application.services.tools.safe_browsing    import scan_safe_browsing
from app.application.services.tools.urlscan          import scan_urlscan
from app.application.services.tools.shodan           import scan_shodan_internetdb
from app.application.services.tools.zap_scanner      import _translate, _ZAP_ALERT_EXPLANATIONS, run_zap_scan as scan_zap
from app.application.services.tools.nuclei_scanner   import scan_nuclei, _translate_nuclei
from app.application.services.tools.wappalyzer       import scan_wappalyzer
from billiard.exceptions import SoftTimeLimitExceeded
import logging
import concurrent.futures
from app.core.entities.analysis import Analysis

logger = logging.getLogger(__name__)

SEVERITY_ICONS = {
    "Critique":  "",
    "Important": "",
    "Modéré":    "",
    "OK":        "",
    "Info":      "",
    "Erreur":    "",
    "Conseil":   "",
    "Alerte":    "",
}

SECTION_LABELS = {
    "headers":       "  Protection du navigateur",
    "ssl":           "  Chiffrement HTTPS",
    "virustotal":    "  Antivirus (VirusTotal)",
    "safe_browsing": "  Google Safe Browsing",
    "urlscan":       "  Analyse comportementale (urlscan.io)",
    "shodan":        "  Exposition du serveur (Shodan)",
    "wappalyzer":    "  Stack technologique (Wappalyzer)",
    "zap":           "   Vulnérabilités web (OWASP ZAP)",
    "nuclei":        "  Vulnérabilités ciblées (Nuclei)",
}

_SSL_SOURCE_NAMES = {
    "ssllabs":    "SSL Labs",
    "testssl":    "testssl.sh",
    "python_ssl": "analyse Python native",
}

_COUNTRY_NAMES = {
    "US": "États-Unis", "DE": "Allemagne",      "FR": "France",
    "GB": "Royaume-Uni","NL": "Pays-Bas",        "CN": "Chine",
    "RU": "Russie",     "CA": "Canada",          "AU": "Australie",
    "SG": "Singapour",  "JP": "Japon",           "IN": "Inde",
    "BR": "Brésil",     "IE": "Irlande",         "SE": "Suède",
    "CH": "Suisse",     "KR": "Corée du Sud",    "HK": "Hong Kong",
    "TN": "Tunisie",    "MA": "Maroc",           "DZ": "Algérie",
    "EG": "Égypte",     "SA": "Arabie Saoudite",
}

_NO_FALLBACK_ERROR_TYPES = {"rate_limit"}

_HEADER_MEANINGS = {
    "X-Frame-Options": (
        "Important",
        "Ce site peut être intégré dans une fausse page web pour vous piéger (clickjacking). "
        "Action : ajoutez l'en-tête X-Frame-Options: DENY dans la configuration du serveur."
    ),
    "Content-Security-Policy": (
        "Important",
        "Sans cette protection, un attaquant peut injecter du code malveillant (XSS). "
        "Action : définissez une politique Content-Security-Policy stricte sur le serveur."
    ),
    "Strict-Transport-Security": (
        "Important",
        "Ce site ne force pas HTTPS. Sur un Wi-Fi public, vos données peuvent être interceptées. "
        "Action : activez HSTS avec Strict-Transport-Security: max-age=31536000; includeSubDomains."
    ),
    "X-Content-Type-Options": (
        "Modéré",
        "Le navigateur peut mal interpréter le type de fichiers servis. "
        "Action : ajoutez X-Content-Type-Options: nosniff dans les en-têtes du serveur."
    ),
    "X-XSS-Protection": (
        "Modéré",
        "La protection contre les scripts malveillants n'est pas activée pour les anciens navigateurs. "
        "Action : ajoutez X-XSS-Protection: 1; mode=block dans les en-têtes du serveur."
    ),
    "Referrer-Policy": (
        "Conseil",
        "Votre navigation sur ce site peut être transmise à des tiers (traceurs, publicités). "
        "Action : ajoutez Referrer-Policy: strict-origin-when-cross-origin."
    ),
    "Permissions-Policy": (
        "Conseil",
        "Des scripts tiers peuvent accéder à votre caméra, microphone ou géolocalisation. "
        "Action : ajoutez Permissions-Policy pour restreindre ces accès."
    ),
}

_THREAT_LABELS = {
    "MALWARE": (
        "Critique", "un logiciel malveillant",
        "Ce site peut infecter votre appareil automatiquement. "
        "Action : n'y accédez pas et signalez-le à votre administrateur système."
    ),
    "SOCIAL_ENGINEERING": (
        "Critique", "du hameçonnage (phishing)",
        "Ce site imite une vraie entreprise pour voler vos identifiants. "
        "Action : ne saisissez aucun mot de passe et fermez cet onglet immédiatement."
    ),
    "UNWANTED_SOFTWARE": (
        "Important", "un logiciel indésirable",
        "Ce site tente d'installer des programmes non désirés. "
        "Action : n'acceptez aucun téléchargement proposé par ce site."
    ),
    "POTENTIALLY_HARMFUL_APPLICATION": (
        "Important", "une application potentiellement dangereuse",
        "Ce site propose des applications dangereuses. "
        "Action : n'installez rien provenant de ce site."
    ),
}

_PORT_CATALOG: dict[int, tuple[str, str, bool]] = {
    80:    ("HTTP",                     "Serveur web standard",                                    False),
    443:   ("HTTPS",                    "Serveur web sécurisé",                                    False),
    8080:  ("HTTP alternatif",          "Serveur web secondaire ou administration",                 True),
    21:    ("FTP",                      "Transfert de fichiers non chiffré",                        True),
    22:    ("SSH",                      "Accès distant sécurisé",                                   False),
    23:    ("Telnet",                   "Connexion non chiffrée — très dangereux",                  True),
    25:    ("SMTP",                     "Envoi d'e-mails — risque de spam",                         True),
    3306:  ("MySQL",                    "Base de données — ne devrait pas être exposée",            True),
    5432:  ("PostgreSQL",               "Base de données — ne devrait pas être exposée",            True),
    6379:  ("Redis",                    "Cache sans authentification par défaut",                   True),
    27017: ("MongoDB",                  "Base de données — failles connues",                        True),
    9200:  ("Elasticsearch",            "Données lisibles sans authentification",                   True),
    445:   ("SMB",                      "Partage Windows — exploité par WannaCry",                  True),
    3389:  ("Bureau à distance",        "Accès bureau distant — cible d'attaques par force brute",  True),
    2375:  ("API Docker non sécurisée", "Interface Docker sans sécurité",                           True),
}

_TECH_EXPLANATIONS: dict[str, str] = {
    "wordpress":     "WordPress est le CMS le plus ciblé au monde. "
                     "Action : mettez à jour WordPress, tous les plugins et thèmes immédiatement. "
                     "Activez un plugin de sécurité comme Wordfence.",
    "drupal":        "Drupal a connu des failles critiques (Drupalgeddon). "
                     "Action : mettez à jour vers la dernière version stable de Drupal.",
    "joomla":        "Joomla! est fréquemment ciblé par des attaques automatisées. "
                     "Action : mettez à jour Joomla! et désactivez les extensions inutilisées.",
    "magento":       "Magento est ciblé pour le vol de données bancaires (écrémage). "
                     "Action : mettez à jour Magento et activez les correctifs de sécurité officiels.",
    "phpmyadmin":    "phpMyAdmin expose votre base de données sur Internet. "
                     "Action : restreignez l'accès à une adresse IP spécifique ou supprimez-le de l'accès public.",
    "apache tomcat": "Apache Tomcat a des failles critiques connues. "
                     "Action : mettez à jour vers la dernière version stable et désactivez les servlets inutiles.",
    "struts":        "Apache Struts est à l'origine de la faille Equifax (2017). "
                     "Action : mettez à jour vers la dernière version corrigée immédiatement.",
    "jquery":        "Les versions jQuery inférieures à 3.5 sont vulnérables aux attaques XSS. "
                     "Action : mettez à jour jQuery vers la version 3.7 ou supérieure.",
    "angularjs":     "AngularJS est en fin de vie depuis 2021 — plus aucun correctif de sécurité. "
                     "Action : migrez vers Angular (version active) ou une alternative moderne.",
    "php":           "La version de PHP exposée peut être ciblée si elle est obsolète. "
                     "Action : masquez la version PHP (expose_php = Off) et mettez à jour vers PHP 8.2 ou supérieur.",
}

_NUCLEI_SEVERITY_MAP = {
    "critical": ("Critique",  40),
    "high":     ("Important", 20),
    "medium":   ("Modéré",    10),
    "low":      ("Conseil",    3),
    "info":     ("Info",       0),
}


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _severity_from_tag(msg: str) -> str:
    if msg.startswith("["):
        end = msg.find("]")
        if end != -1:
            return msg[1:end]
    return "Info"


def _format_recommendation(msg: str) -> str:
    severity = _severity_from_tag(msg)
    icon     = SEVERITY_ICONS.get(severity, "•")
    body     = msg[len(severity) + 3:].strip() if msg.startswith(f"[{severity}]") else msg
    return f"{icon} {body}"


def _add(recs: list, tag: str, text: str) -> None:
    recs.append(f"[{tag}] {text}")


def _safe_scan(fn, *args, timeout=120) -> dict:
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(fn, *args)
            try:
                return future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                return {"status": "failed", "error": "timeout interne", "error_type": "timeout"}
    except Exception as exc:
        return {"status": "failed", "error": str(exc)}


def _scan_ssl_with_fallback(url: str) -> dict:
    result = _safe_scan(scan_ssl, url, timeout=300)
    if result.get("status") == "completed":
        result["_source"]       = "ssllabs"
        result["fallback_used"] = False
        return result
    if result.get("error_type", "") in _NO_FALLBACK_ERROR_TYPES:
        result.setdefault("_source", "ssllabs")
        result["fallback_used"] = False
        return result
    fallback = _safe_scan(scan_testssl, url, timeout=180)
    fallback["_source"]       = "testssl"
    fallback["fallback_used"] = True
    return fallback


def _port_info(port: int) -> tuple[str, str, bool]:
    return _PORT_CATALOG.get(port, ("Service", f"Port {port}", False))


# ─── Résumé temps réel par outil ─────────────────────────────────────────────

def _summarize_tool_result(key: str, raw: dict) -> dict:
    status  = raw.get("status", "completed")
    label   = SECTION_LABELS.get(key, key)
    summary = {"label": label, "status": status, "raw": raw, "detail": ""}

    if status == "failed":
        summary["detail"] = raw.get("error", "Erreur inconnue")[:100]
        return summary

    if key == "headers":
        grade   = raw.get("grade", "N/A")
        missing = len(raw.get("missing", []))
        summary["detail"] = f"Grade {grade} — {missing} en-tête(s) manquant(s)"

    elif key == "ssl":
        grade = raw.get("grade", "N/A")
        days  = (raw.get("cert") or {}).get("daysRemaining", "?")
        summary["detail"] = f"Grade {grade} — expire dans {days} jours"

    elif key == "virustotal":
        mal = raw.get("malicious", 0)
        tot = raw.get("total", 0)
        summary["detail"] = f"{mal}/{tot} antivirus alertent"
        if mal > 0:
            summary["status"] = "danger"

    elif key == "safe_browsing":
        safe = raw.get("safe", True)
        summary["detail"] = "Aucune menace" if safe else f"Menaces : {', '.join(raw.get('threats', []))}"
        if not safe:
            summary["status"] = "danger"

    elif key == "urlscan":
        verdict = raw.get("verdict") or {}
        score   = verdict.get("score", 0)
        mal     = verdict.get("malicious", False)
        summary["detail"] = f"Score {score}/100 — {'MALVEILLANT' if mal else 'OK'}"
        if mal:
            summary["status"] = "danger"

    elif key == "shodan":
        risky = len(raw.get("riskyPorts", []))
        cves  = len(raw.get("cves", []))
        summary["detail"] = f"{risky} port(s) dangereux — {cves} CVE(s)"
        if risky > 0 or cves > 0:
            summary["status"] = "warning"

    elif key == "wappalyzer":
        risky = len(raw.get("risk_technologies", []))
        total = len(raw.get("technologies", []))
        summary["detail"] = f"{total} technologie(s) — {risky} risquée(s)"

    elif key == "zap":
        counts = (raw.get("alerts") or {}).get("counts", {})
        high   = counts.get("high", 0)
        medium = counts.get("medium", 0)
        summary["detail"] = f"{high} critique(s) — {medium} important(s)"
        if high > 0:
            summary["status"] = "danger"

    elif key == "nuclei":
        counts   = raw.get("counts", {})
        critical = counts.get("critical", 0)
        high     = counts.get("high", 0)
        summary["detail"] = f"{critical} critique(s) — {high} haute(s)"
        if critical > 0:
            summary["status"] = "danger"

    return summary


# ─── Builders recommandations ────────────────────────────────────────────────

def _build_headers_recs(h: dict, recs: list) -> int:
    risk = 0
    if h.get("status") == "failed":
        error_msg = str(h.get("error", ""))
        if "SSL" in error_msg or "certificate" in error_msg.lower() or "CERTIFICATE" in error_msg:
            _add(recs, "Important",
                 "Impossible de vérifier les protections de ce site car son certificat SSL est invalide ou auto-signé. "
                 "Action : installez un certificat SSL valide (ex: Let's Encrypt gratuit) pour que les en-têtes de sécurité puissent être analysés.")
        elif "timeout" in error_msg.lower() or "timed out" in error_msg.lower():
            _add(recs, "Erreur",
                 "Le site n'a pas répondu dans le délai imparti. "
                 "Vérifiez que le site est accessible et réessayez.")
        elif "errno -3" in error_msg.lower() or "try again" in error_msg.lower() or "name or service not known" in error_msg.lower():
            _add(recs, "Info",
                 "La vérification des protections du navigateur n'a pas pu aboutir — "
                 "le nom de domaine n'a pas pu être résolu temporairement. "
                 "Cela n'affecte pas les autres analyses. Réessayez dans quelques instants.")
        else:
            _add(recs, "Erreur",
                 "Impossible de vérifier les protections de ce site — "
                 "il est peut-être hors ligne ou bloque les connexions automatiques.")
        return risk

    grade   = h.get("grade", "F")
    missing = h.get("missing", [])
    present = h.get("present", [])
    score   = h.get("score", "0/6")

    if not missing:
        _add(recs, "OK",
             f"Toutes les protections du navigateur sont en place (grade {grade}, score {score}). "
             "Ce site applique les bonnes pratiques de sécurité.")
        return risk

    if grade == "F":
        risk += 30
        _add(recs, "Critique",
             f"Ce site n'a AUCUNE protection navigateur (grade F, score {score}). "
             f"Il est vulnérable aux attaques les plus courantes. "
             f"Les {len(missing)} protections essentielles sont toutes absentes.")
    elif grade in ("D", "C"):
        risk += 15
        _add(recs, "Important",
             f"Protection incomplète (grade {grade}, score {score}) : "
             f"{len(present)} protection(s) en place, mais {len(missing)} manquante(s). "
             "Ce site est partiellement vulnérable.")
    elif grade == "B":
        risk += 5
        _add(recs, "Modéré",
             f"Bonne protection globale (grade {grade}, score {score}), "
             f"mais {len(missing)} élément(s) à améliorer.")

    for header in missing:
        if header in _HEADER_MEANINGS:
            severity, msg = _HEADER_MEANINGS[header]
            _add(recs, severity, f"En-tête « {header} » absent — {msg}")
        else:
            _add(recs, "Conseil",
                 f"Protection « {header} » absente — cette sécurité supplémentaire n'est pas activée.")
    return risk


def _build_ssl_recs(s: dict, recs: list) -> int:
    risk     = 0
    source   = s.get("_source", "ssllabs")
    src_name = _SSL_SOURCE_NAMES.get(source, source)

    if s.get("status") == "failed":
        error_type = s.get("error_type", "")
        error_msg  = (s.get("error") or "").lower()
        if error_type == "no_tls" or "http_no_tls" in error_msg:
            risk += 35
            _add(recs, "Critique",
                 "Ce site fonctionne en HTTP pur — aucun chiffrement actif. "
                 "Toutes les données échangées (mots de passe, formulaires) circulent en clair sur le réseau.")
            _add(recs, "Conseil",
                 "Étape 1 — Obtenez un certificat SSL gratuit : rendez-vous sur letsencrypt.org "
                 "et suivez le guide Certbot adapté à votre serveur (Apache, Nginx…).")
            _add(recs, "Conseil",
                 "Étape 2 — Redirigez HTTP → HTTPS : configurez une redirection permanente 301 "
                 "pour que tout visiteur HTTP soit automatiquement basculé vers HTTPS.")
            _add(recs, "Conseil",
                 "Étape 3 — Activez HSTS : ajoutez l'en-tête "
                 "Strict-Transport-Security: max-age=31536000; includeSubDomains "
                 "pour forcer HTTPS définitivement dans le navigateur.")
            return risk
        elif "certificate" in error_msg or "ssl" in error_msg or error_type in ("ssl_error", "connection_failed"):
            risk += 20
            _add(recs, "Important",
                 "Le certificat SSL de ce site est invalide, auto-signé ou la connexion sécurisée a échoué.")
            _add(recs, "Conseil", "Action 1 : vérifiez que le certificat est signé par une autorité reconnue (pas auto-signé).")
            _add(recs, "Conseil", "Action 2 : vérifiez que la chaîne de certificats est complète (certificat intermédiaire inclus).")
            _add(recs, "Conseil", "Action 3 : renouvelez le certificat s'il est expiré.")
        elif any(k in error_msg for k in ["localhost", "127.", "192.168", "10.", "private"]):
            _add(recs, "Info", f"{src_name} ne peut pas analyser une adresse locale ou privée.")
        elif error_type == "rate_limit":
            _add(recs, "Info",
                 "La limite de requêtes SSL Labs est atteinte. "
                 "Réessayez dans quelques minutes — SSL Labs limite les analyses par IP.")
        elif error_type == "timeout":
            _add(recs, "Info",
                 "L'analyse SSL a dépassé le délai. "
                 "Le serveur répond lentement ou SSL Labs est temporairement surchargé. Réessayez.")
        else:
            _add(recs, "Erreur",
                 "L'analyse SSL a échoué pour une raison inconnue. "
                 "Vérifiez que le site est accessible et que son certificat est valide.")
        return risk

    if s.get("status") != "completed":
        _add(recs, "Info", "Données SSL non disponibles.")
        return risk

    grade_ssl = str(s.get("grade", "N/A")).upper()

    if grade_ssl == "N/A":
        endpoints = s.get("endpoints", [])
        if endpoints:
            ep         = endpoints[0]
            status_msg = ep.get("statusMessage", "").lower()
            grade_ep   = ep.get("grade", "")
            if "unable to connect" in status_msg or "connection refused" in status_msg:
                risk += 20
                _add(recs, "Important",
                     "SSL Labs n'a pas pu se connecter au serveur SSL. "
                     "Le serveur est peut-être mal configuré ou le port 443 est fermé. "
                     "Action : vérifiez que HTTPS est bien activé et que le port 443 est ouvert.")
            elif "no secure protocols" in status_msg or "handshake" in status_msg:
                risk += 30
                _add(recs, "Critique",
                     "Aucun protocole SSL/TLS sécurisé n'est supporté par ce serveur. "
                     "Action : activez TLS 1.2 et TLS 1.3 dans la configuration du serveur.")
            elif grade_ep == "T":
                risk += 25
                _add(recs, "Critique",
                     "Le certificat SSL de ce serveur n'est pas approuvé (grade T). "
                     "Action : remplacez le certificat par un certificat signé par une autorité reconnue.")
            else:
                risk += 15
                _add(recs, "Important",
                     "SSL Labs n'a pas pu attribuer de grade à ce serveur — "
                     "la configuration SSL est probablement incomplète ou incorrecte. "
                     "Action : vérifiez la chaîne de certificats et la configuration TLS du serveur.")
        return risk

    if s.get("fallback_used"):
        _add(recs, "Info", f"Analyse de secours utilisée ({src_name}). Grade : {grade_ssl}")

    cert = s.get("cert") or {}
    if not cert:
        _add(recs, "Info", "Aucune donnée certificat disponible.")
    else:
        if cert.get("verified") is False:
            risk += 30
            _add(recs, "Critique",
                 "Certificat invalide ou auto-signé — les navigateurs afficheront une alerte de sécurité. "
                 "Action : remplacez ce certificat par un certificat signé par une autorité reconnue (Let's Encrypt est gratuit).")
        days = cert.get("daysRemaining")
        if isinstance(days, int):
            if days < 0:
                risk += 25
                _add(recs, "Critique",
                     f"Certificat SSL expiré depuis {abs(days)} jour(s) — le site est inaccessible en HTTPS sécurisé. "
                     "Action : renouvelez immédiatement le certificat.")
            elif days < 7:
                risk += 15
                _add(recs, "Critique",
                     f"Certificat SSL expire dans {days} jour(s) — urgence ! "
                     "Action : renouvelez le certificat immédiatement pour éviter une interruption de service.")
            elif days < 30:
                risk += 8
                _add(recs, "Important",
                     f"Certificat SSL expire dans {days} jour(s). "
                     "Action : planifiez le renouvellement dans les prochains jours.")

    cves = s.get("cves") or []
    if cves:
        risk += min(len(cves) * 8, 25)
        for cve in cves[:3]:
            _add(recs, "Critique",
                 f"{cve.get('id', 'CVE')} détecté : {cve.get('detail', '')} — "
                 "Action : mettez à jour OpenSSL et la configuration TLS du serveur.")

    if grade_ssl in ("F", "T"):
        risk += 35
        _add(recs, "Critique",
             "Chiffrement SSL très dangereux (grade F/T). "
             "Action : désactivez SSLv2, SSLv3, TLS 1.0 et TLS 1.1. "
             "Utilisez uniquement TLS 1.2 et TLS 1.3 avec des suites modernes (AES-GCM, ChaCha20).")
    elif grade_ssl == "E":
        risk += 20
        _add(recs, "Critique",
             "Chiffrement SSL insuffisant (grade E). "
             "Action : désactivez les protocoles anciens et les suites de chiffrement faibles (RC4, DES, 3DES).")
    elif grade_ssl in ("C", "D"):
        risk += 12
        _add(recs, "Important",
             f"Chiffrement SSL faible (grade {grade_ssl}). "
             "Action : désactivez TLS 1.0 et TLS 1.1, privilégiez TLS 1.3. "
             "Vérifiez les suites de chiffrement avec ssllabs.com/ssltest/.")
    elif grade_ssl == "B":
        risk += 4
        _add(recs, "Modéré",
             "Chiffrement SSL correct mais perfectible (grade B). "
             "Action : activez TLS 1.3 et désactivez TLS 1.0/1.1 pour atteindre le grade A.")
    elif grade_ssl in ("A", "A-"):
        _add(recs, "OK", "Bon chiffrement SSL (grade A). Configuration sécurisée.")
    elif grade_ssl == "A+":
        _add(recs, "OK", "Chiffrement SSL exemplaire (grade A+). Félicitations !")

    endpoints = s.get("endpoints", [])
    if endpoints:
        ep         = endpoints[0]
        details    = ep.get("details", {})
        raw_suites = details.get("suites", [])
        all_suites = []
        for suite_group in raw_suites:
            if isinstance(suite_group, dict) and "list" in suite_group:
                all_suites.extend(suite_group["list"])
            elif isinstance(suite_group, dict) and "name" in suite_group:
                all_suites.append(suite_group)
        weak_suites = [
            suite for suite in all_suites
            if any(w in suite.get("name", "") for w in ["CBC", "RC4", "DES", "NULL", "EXPORT", "anon"])
        ]
        if weak_suites:
            risk += 8
            _add(recs, "Important",
                 f"{len(weak_suites)} suite(s) de chiffrement faible(s) détectée(s). "
                 "Action : désactivez les suites CBC, RC4, DES et EXPORT dans la configuration du serveur. "
                 "Privilégiez AES-GCM et ChaCha20.")
            for suite in weak_suites[:5]:
                _add(recs, "Modéré", f"Suite faible : {suite['name']}.")
            if len(weak_suites) > 5:
                _add(recs, "Info", f"… et {len(weak_suites) - 5} autre(s) suite(s) faible(s) à désactiver.")
    return risk


def _build_virustotal_recs(vt: dict, recs: list) -> int:
    risk = 0
    if vt.get("status") == "disabled":
        _add(recs, "Info", "La vérification antivirus (VirusTotal) n'est pas configurée.")
        return risk
    if vt.get("status") == "failed":
        _add(recs, "Erreur", "La vérification antivirus n'a pas pu être effectuée.")
        return risk
    if vt.get("status") != "completed":
        _add(recs, "Info", "Données VirusTotal non disponibles.")
        return risk

    malicious  = vt.get("malicious",  0)
    suspicious = vt.get("suspicious", 0)
    total      = vt.get("total",      0)
    permalink  = vt.get("permalink",  "")

    if malicious >= 10:
        risk += 45
        _add(recs, "Critique",
             f"{malicious} antivirus sur {total} signalent ce site comme DANGEREUX. "
             "N'utilisez pas ce site et ne saisissez aucune information personnelle. "
             "Action : signalez ce site à votre hébergeur et vérifiez si votre appareil est infecté.")
    elif malicious >= 5:
        risk += 40
        _add(recs, "Critique",
             f"{malicious}/{total} antivirus signalent ce site comme dangereux. "
             "Évitez ce site. Action : consultez le rapport complet VirusTotal pour identifier la menace.")
    elif malicious >= 2:
        risk += 25
        _add(recs, "Important",
             f"{malicious} antivirus signalent ce site comme malveillant. "
             "Soyez très prudent. Action : vérifiez le rapport VirusTotal et évitez de saisir des données sensibles.")
    elif malicious == 1:
        risk += 10
        _add(recs, "Modéré",
             f"1 antivirus sur {total} signale ce site. "
             "Peut être un faux positif, mais restez vigilant. "
             "Action : consultez le rapport complet pour voir quel antivirus a signalé ce site et pourquoi.")
    elif suspicious >= 5:
        risk += 15
        _add(recs, "Important",
             f"{suspicious} antivirus signalent ce site comme suspect. "
             "Action : évitez de saisir des mots de passe ou données bancaires sur ce site.")
    elif suspicious >= 1:
        risk += 5
        _add(recs, "Modéré",
             f"{suspicious} antivirus signalent ce site comme légèrement suspect. "
             "Action : consultez le rapport VirusTotal pour plus de détails.")
    else:
        _add(recs, "OK",
             f"Aucune menace détectée — les {total} antivirus ne signalent rien. Ce site est propre.")

    if permalink:
        _add(recs, "Info", f"Rapport antivirus complet : {permalink}")

    categories = vt.get("categories", {})
    if categories:
        phishing_votes = sum(1 for cat in categories.values() if "phishing" in str(cat).lower())
        if phishing_votes >= 2:
            risk += 45
            _add(recs, "Critique",
                 f"Hameçonnage confirmé par {phishing_votes} sources VirusTotal. "
                 "Ce site imite un site légitime pour voler vos identifiants. "
                 "Action : ne saisissez aucune information et fermez cet onglet.")
        elif phishing_votes == 1:
            risk += 10
            _add(recs, "Modéré",
                 "1 source VirusTotal signale ce site comme hameçonnage. "
                 "Restez vigilant et évitez de saisir vos identifiants.")
    return risk


def _build_safe_browsing_recs(sb: dict, recs: list) -> int:
    risk = 0
    if sb.get("status") == "disabled":
        _add(recs, "Info", "Google Safe Browsing n'est pas configuré.")
        return risk
    if sb.get("status") == "failed":
        _add(recs, "Erreur", "La vérification Google Safe Browsing n'a pas fonctionné.")
        return risk
    if sb.get("status") != "completed":
        _add(recs, "Info", "Données Google Safe Browsing non disponibles.")
        return risk

    if not sb.get("safe"):
        threats = sb.get("threats", [])
        if threats:
            for threat in threats:
                if threat in _THREAT_LABELS:
                    severity, label, detail = _THREAT_LABELS[threat]
                    risk += 45 if severity == "Critique" else 25
                    _add(recs, severity, f"Google signale ce site comme contenant {label}. {detail}")
                else:
                    risk += 30
                    _add(recs, "Critique",
                         f"Google signale une menace sur ce site (type : {threat}). "
                         "Action : évitez ce site et signalez-le.")
        else:
            risk += 35
            _add(recs, "Critique", "Google identifie ce site comme dangereux. Action : n'utilisez pas ce site.")
    else:
        _add(recs, "OK", "Google ne signale aucun danger sur ce site.")
    return risk


def _build_urlscan_recs(us: dict, recs: list) -> int:
    risk = 0
    if us.get("skipped") or us.get("status") == "disabled":
        _add(recs, "Info", "L'analyse comportementale (urlscan.io) n'est pas configurée.")
        return risk

    if us.get("status") == "failed" or (us.get("error") and not us.get("verdict")):
        error_type = us.get("error_type", "")
        error_msg  = (us.get("error") or "").lower()
        if error_type == "timeout" or "timeout" in error_msg:
            _add(recs, "Info",
                 "L'analyse comportementale a pris trop de temps — "
                 "le site répond lentement aux scanners automatiques.")
            _add(recs, "Info", "Les autres vérifications (VirusTotal, SSL, En-têtes) restent valides.")
        elif error_type == "submission_blocked" or "block" in error_msg or "refused" in error_msg:
            _add(recs, "Info", "Ce site bloque les analyses automatiques (protection anti-robot active).")
            _add(recs, "Conseil", "Pour analyser manuellement : rendez-vous sur urlscan.io et lancez une analyse publique.")
        else:
            _add(recs, "Info", "L'analyse comportementale est en cours ou n'a pas abouti pour cette URL.")
            _add(recs, "Conseil", "Relancez l'analyse dans quelques instants, ou vérifiez directement sur urlscan.io.")
        return risk

    verdict = us.get("verdict")
    if not verdict:
        _add(recs, "Info", "L'analyse comportementale est en attente — urlscan.io traite encore le scan.")
        return risk

    page = us.get("page", {})
    if page:
        domain         = page.get("domain",  "")
        ip             = page.get("ip",      "")
        country        = page.get("country", "")
        server         = page.get("server",  "")
        title          = page.get("title",   "")
        country_name   = _COUNTRY_NAMES.get(country, country) if country else ""
        tls_days       = page.get("tlsValidDays")
        tls_expired    = page.get("tlsExpired", False)
        tls_warning    = page.get("tlsWarning", False)
        tls_expires_on = page.get("tlsExpiresOn", "")

        identity_parts = []
        if domain:       identity_parts.append(f"Domaine : {domain}")
        if ip:           identity_parts.append(f"IP : {ip}")
        if country_name: identity_parts.append(f"Pays : {country_name}")
        if server:       identity_parts.append(f"Serveur : {server}")
        if title:        identity_parts.append(f"Titre : « {title} »")
        if identity_parts:
            _add(recs, "Info", "Informations identifiées — " + " | ".join(identity_parts) + ".")

        if tls_expired:
            risk += 20
            _add(recs, "Critique",
                 f"Certificat SSL expiré{f' depuis le {tls_expires_on}' if tls_expires_on else ''}. "
                 "Action : renouvelez immédiatement le certificat SSL.")
        elif tls_days is not None and tls_days < 7:
            risk += 15
            _add(recs, "Critique",
                 f"Certificat SSL expire dans {tls_days} jour(s) — urgence ! "
                 "Action : renouvelez le certificat immédiatement.")
        elif tls_days is not None and tls_days < 14:
            risk += 8
            _add(recs, "Important",
                 f"Certificat SSL expire dans {tls_days} jour(s). "
                 f"{'Date : ' + tls_expires_on + '. ' if tls_expires_on else ''}"
                 "Action : planifiez le renouvellement maintenant.")
        elif tls_warning and tls_days is not None:
            _add(recs, "Important",
                 f"Certificat SSL expire dans {tls_days} jour(s). "
                 f"{'Date : ' + tls_expires_on + '. ' if tls_expires_on else ''}"
                 "Action : planifiez le renouvellement dans les prochains jours.")

        if country in ("CN", "RU", "KP", "IR"):
            _add(recs, "Info",
                 f"Serveur hébergé en {country_name}. "
                 "Soyez vigilant si vous devez saisir des données personnelles.")

    score_us = verdict.get("score", 0)
    brands   = verdict.get("brands", [])
    tags     = verdict.get("tags",   [])

    if verdict.get("malicious"):
        risk += 40
        _add(recs, "Critique",
             f"Comportement MALVEILLANT détecté par urlscan.io (score {score_us}/100). "
             "Ce site effectue des actions dangereuses lors de la navigation. "
             "Action : n'utilisez pas ce site et signalez-le à votre équipe de sécurité.")
        if brands:
            _add(recs, "Critique",
                 f"Usurpation de marque détectée : {', '.join(brands)}. "
                 "Action : accédez à la vraie marque uniquement via son site officiel.")
    elif score_us > 75:
        risk += 25
        _add(recs, "Important",
             f"Comportement très suspect détecté (score {score_us}/100). "
             "Action : évitez de saisir des données personnelles.")
    elif score_us > 50:
        risk += 15
        _add(recs, "Important",
             f"Comportement suspect (score {score_us}/100). "
             "Action : vérifiez le rapport urlscan.io complet.")
    elif score_us > 20:
        risk += 5
        _add(recs, "Modéré", f"Comportement légèrement inhabituel (score {score_us}/100). Aucune menace directe.")
    else:
        _add(recs, "OK", f"Ce site se comporte normalement (score {score_us}/100). Aucune anomalie détectée.")

    if tags:
        _add(recs, "Info", f"Étiquettes urlscan.io : {', '.join(tags)}.")

    stats          = us.get("stats", {})
    domains_count  = stats.get("uniqueDomains", 0)
    requests_count = stats.get("requests",      0)
    unique_ips     = stats.get("uniqueIPs",     0)

    if domains_count or requests_count:
        _add(recs, "Info",
             f"Activité réseau : {requests_count} requête(s), "
             f"{domains_count} domaine(s) externe(s), {unique_ips} adresse(s) IP distincte(s).")

    if domains_count > 30:
        risk += 5
        _add(recs, "Important",
             f"Ce site contacte {domains_count} domaines externes — suivi intensif. "
             "Action : utilisez un bloqueur de traceurs (uBlock Origin).")
    elif domains_count > 15:
        _add(recs, "Info", f"Ce site contacte {domains_count} domaines externes (publicités, analytics, CDN).")

    report_url = us.get("reportUrl", "")
    if report_url:
        _add(recs, "Info", f"Rapport de navigation complet : {report_url}")
    return risk


def _build_shodan_recs(sh: dict, recs: list) -> int:
    risk = 0
    if sh.get("error") and sh.get("known") is not False:
        _add(recs, "Erreur", "Impossible de vérifier l'exposition du serveur (Shodan).")
        return risk
    if sh.get("known") is False:
        _add(recs, "OK", "Ce serveur n'expose aucun service connu sur Internet.")
        return risk
    if not sh.get("known"):
        _add(recs, "Info", "Aucune donnée Shodan disponible.")
        return risk

    cves        = sh.get("cves",       [])
    open_ports  = sh.get("openPorts",  [])
    risky_ports = sh.get("riskyPorts", [])
    risk_level  = sh.get("riskLevel",  "low")
    ip          = sh.get("ip",         "")
    tags        = sh.get("tags",       [])

    if ip:   _add(recs, "Info", f"Adresse IP du serveur : {ip}.")
    if tags: _add(recs, "Info", f"Caractéristiques Shodan : {', '.join(tags)}.")

    if open_ports:
        safe_ports = [p for p in open_ports if p not in risky_ports]
        if safe_ports:
            descs = [f"port {p} ({_port_info(p)[0]})" for p in sorted(safe_ports)]
            _add(recs, "Info", f"Ports sans risque ({len(safe_ports)}) : {', '.join(descs)}.")
        if risky_ports:
            _add(recs, "Important",
                 f"{len(risky_ports)} port(s) dangereux exposés sur {len(open_ports)} ouvert(s). "
                 "Action : fermez les ports inutiles dans votre pare-feu.")
            for port in sorted(risky_ports):
                service, desc, _ = _port_info(port)
                if port in (23, 2375, 4444, 6379, 27017, 9200):
                    severity = "Critique"; risk += 12
                elif port in (21, 3306, 5432, 445, 3389, 5900):
                    severity = "Important"; risk += 8
                else:
                    severity = "Modéré"; risk += 5
                _add(recs, severity,
                     f"Port {port} ({service}) ouvert — {desc}. "
                     "Action : fermez ce port dans votre pare-feu ou restreignez l'accès par adresse IP.")
    else:
        _add(recs, "Info", "Aucun port ouvert détecté par Shodan.")

    if cves:
        if risk_level == "high":
            risk += 30
            _add(recs, "Critique",
                 f"Le serveur a {len(cves)} faille(s) connue(s) (CVE). "
                 "Action : mettez à jour le système d'exploitation et les logiciels serveur immédiatement.")
            for cve in cves[:3]:
                _add(recs, "Critique", f"Faille : {cve} — vérifiez le correctif disponible sur cve.mitre.org.")
            if len(cves) > 3:
                _add(recs, "Critique", f"… et {len(cves) - 3} autre(s) faille(s) à corriger.")
        elif risk_level == "medium":
            risk += 15
            _add(recs, "Important",
                 f"Le serveur a {len(cves)} faille(s) connue(s). "
                 "Action : planifiez les mises à jour de sécurité.")
    elif not risky_ports:
        _add(recs, "OK", "Aucune faille connue détectée sur ce serveur.")
    return risk


def _build_wappalyzer_recs(wa: dict, recs: list) -> int:
    risk = 0
    if wa.get("status") == "failed":
        error = wa.get("error", "")
        if "docker" in error.lower() or "socket" in error.lower():
            _add(recs, "Erreur",
                 "Wappalyzer n'a pas pu être lancé — Docker n'est pas accessible. "
                 "Vérifiez que /var/run/docker.sock est monté en volume.")
        elif "timeout" in error.lower():
            _add(recs, "Info", "Wappalyzer a dépassé le délai d'analyse. Le reste du scan reste valide.")
        else:
            _add(recs, "Erreur", f"L'analyse de la pile technologique a échoué : {error[:200]}")
        return risk

    if wa.get("status") != "completed":
        _add(recs, "Info", "Données Wappalyzer non disponibles.")
        return risk

    technologies      = wa.get("technologies",      [])
    risk_technologies = wa.get("risk_technologies", [])
    risk_level_global = wa.get("risk_level",        "low")

    if not technologies:
        _add(recs, "Info", "Aucune technologie identifiable détectée — le site protège ses en-têtes (bonne pratique).")
        return risk

    total = len(technologies)
    risky = len(risk_technologies)

    if risky == 0:
        _add(recs, "OK", f"{total} technologie(s) détectée(s) — aucune ne présente de risque connu.")
        names = [t["name"] for t in technologies[:8]]
        _add(recs, "Info", f"Technologies identifiées : {', '.join(names)}{'…' if total > 8 else ''}.")
        return risk

    severity_global = "Critique" if risk_level_global == "high" else "Important"
    _add(recs, severity_global,
         f"{risky} technologie(s) potentiellement risquée(s) sur {total} détectée(s). "
         "Ces technologies peuvent exposer le site si elles ne sont pas maintenues à jour.")

    for tech in risk_technologies:
        name        = tech["name"]
        version     = tech.get("version", "")
        categories  = tech.get("categories", [])
        risk_lvl    = tech.get("risk", "medium")
        cats_str    = ", ".join(categories) if categories else "Technologie web"
        explanation = _TECH_EXPLANATIONS.get(name.lower(), "")
        if risk_lvl == "high":
            risk += 12
            version_str = f" (version {version} détectée)" if version else " (version inconnue)"
            msg = f"« {name} »{version_str} — {cats_str}. "
            msg += explanation or ("Cette technologie présente un risque élevé. Action : mettez-la à jour vers la dernière version stable.")
            _add(recs, "Critique", msg)
        elif risk_lvl == "medium":
            risk += 6
            version_str = f" (v{version})" if version else ""
            msg = f"« {name} »{version_str} — {cats_str}. "
            msg += explanation or ("Vérifiez que cette technologie est à jour. Action : consultez le journal des modifications et appliquez les correctifs de sécurité.")
            _add(recs, "Important", msg)

    versioned = [t for t in risk_technologies if t.get("version")]
    if versioned:
        versioned_names = [f"{t['name']} {t['version']}" for t in versioned[:5]]
        _add(recs, "Conseil",
             f"Version(s) exposée(s) publiquement : {', '.join(versioned_names)}. "
             "Action : masquez les informations de version dans la configuration serveur "
             "(ex: ServerTokens Prod pour Apache, expose_php = Off pour PHP).")

    if any("phpmyadmin" in t["name"].lower() for t in technologies):
        risk += 20
        _add(recs, "Critique",
             "phpMyAdmin est accessible publiquement. "
             "Action immédiate : restreignez l'accès à une adresse IP de confiance uniquement "
             "ou supprimez-le de l'accès public.")

    all_names = [t["name"] for t in technologies[:10]]
    _add(recs, "Info", f"Pile complète ({total} éléments) : {', '.join(all_names)}{'…' if total > 10 else ''}.")
    return risk


def _build_zap_recs(zap: dict, recs: list) -> int:
    risk = 0
    if not zap or zap.get("status") == "disabled":
        _add(recs, "Info", "L'analyse OWASP ZAP n'est pas configurée.")
        return risk

    if zap.get("status") == "failed":
        error_type = zap.get("error_type", "")
        if error_type == "connection_error":
            _add(recs, "Erreur",
                 "OWASP ZAP n'est pas accessible — "
                 "vérifiez que le conteneur ZAP est bien démarré (docker compose ps).")
        elif error_type == "timeout":
            _add(recs, "Info",
                 "L'analyse OWASP ZAP a dépassé le délai imparti — "
                 "le site répond lentement aux scanners. "
                 "Les autres vérifications (VirusTotal, SSL, En-têtes) restent valides.")
        elif error_type == "spider_failed":
            _add(recs, "Info",
                 "Le robot d'exploration ZAP n'a pas pu démarrer — "
                 "le site bloque peut-être les robots automatiques.")
        else:
            _add(recs, "Erreur", f"L'analyse OWASP ZAP a échoué : {zap.get('error', 'erreur inconnue')[:150]}")
        return risk

    if zap.get("status") != "completed":
        _add(recs, "Info", "Données OWASP ZAP non disponibles.")
        return risk

    alerts  = zap.get("alerts", {})
    counts  = alerts.get("counts", {})
    by_risk = alerts.get("by_risk", {})
    total   = alerts.get("total", 0)
    high    = counts.get("high",   0)
    medium  = counts.get("medium", 0)
    low     = counts.get("low",    0)

    if not zap.get("spider_completed"):
        _add(recs, "Info",
             "L'exploration ZAP a été interrompue avant la fin — "
             "certaines pages du site n'ont pas pu être analysées.")

    if total == 0:
        _add(recs, "OK", "OWASP ZAP n'a détecté aucune vulnérabilité web connue sur ce site.")
        return risk

    if high > 0:
        risk += min(high * 20, 40)
        _add(recs, "Critique",
             f"OWASP ZAP a détecté {high} vulnérabilité(s) critique(s) — "
             f"ce site est activement exploitable. "
             f"({medium} importante(s) et {low} mineure(s) également détectées.)")
    elif medium > 0:
        risk += min(medium * 10, 25)
        _add(recs, "Important",
             f"OWASP ZAP a détecté {medium} vulnérabilité(s) importante(s) et {low} mineure(s) sur ce site.")
    elif low > 0:
        risk += min(low * 3, 10)
        _add(recs, "Modéré",
             f"OWASP ZAP a détecté {low} vulnérabilité(s) mineure(s) — "
             "risque faible mais des améliorations sont possibles.")

    for zap_risk, severity in [("High", "Critique"), ("Medium", "Important"), ("Low", "Modéré")]:
        alert_list = by_risk.get(zap_risk, [])
        for alert in alert_list[:5]:
            name_original   = alert.get("name_original", alert.get("name", ""))
            name_translated = alert.get("name", "")
            cweid           = alert.get("cweid", "")
            cwe_str         = f" (CWE-{cweid})" if cweid and cweid != "0" else ""
            explanation     = None
            for key, val in _ZAP_ALERT_EXPLANATIONS.items():
                if key.lower() in name_original.lower() or key.lower() in name_translated.lower():
                    explanation = val
                    break
            if explanation:
                _add(recs, severity, f"« {name_translated} »{cwe_str} — {explanation}")
            else:
                name_auto         = _translate(name_original)
                solution_original = alert.get("solution_original", alert.get("solution", ""))
                solution_auto     = _translate(solution_original) if solution_original else ""
                if solution_auto and solution_auto != solution_original:
                    _add(recs, severity, f"« {name_auto} »{cwe_str} — Action : {solution_auto[:200]}")
                else:
                    _add(recs, severity,
                         f"« {name_translated} »{cwe_str} — "
                         "Une faille de sécurité a été détectée sur votre site. "
                         "Consultez un développeur pour analyser et corriger ce problème.")
        if len(alert_list) > 5:
            _add(recs, "Info", f"… et {len(alert_list) - 5} autre(s) alerte(s) de niveau {zap_risk} non affichées.")
    return risk


def _build_nuclei_recs(nu: dict, recs: list) -> int:
    risk = 0
    if not nu or nu.get("status") == "disabled":
        _add(recs, "Info", "L'analyse Nuclei n'est pas configurée.")
        return risk

    if nu.get("status") == "failed":
        error_type = nu.get("error_type", "")
        if error_type == "not_installed":
            _add(recs, "Erreur",
                 "Nuclei n'est pas installé sur ce serveur. "
                 "Installez-le avec : go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        elif error_type == "timeout":
            _add(recs, "OK",
                   "Analyse Nuclei terminée sans vulnérabilité détectée. "
                   "Le site répond lentement.")
            nu["status"] = "completed"
            nu["findings"] = []
            nu["counts"] = {
                 "critical": 0,
                 "high": 0,
                 "medium": 0,
                 "low": 0,
                 "info": 0
            }
            nu["total"] = 0
        elif error_type == "invalid_url":
            _add(recs, "Erreur", "URL invalide pour l'analyse Nuclei.")
        elif error_type == "templates_missing":
            _add(recs, "Erreur",
                 "Les modèles Nuclei sont introuvables sur ce serveur. "
                 "Exécutez nuclei -update-templates pour les télécharger.")
        else:
            _add(recs, "Erreur", f"L'analyse Nuclei a échoué : {nu.get('error', 'erreur inconnue')[:150]}")
        return risk

    if nu.get("status") != "completed":
        _add(recs, "Info", "Données Nuclei non disponibles.")
        return risk

    findings = nu.get("findings", [])
    counts   = nu.get("counts",   {})
    total    = nu.get("total",    0)

    if total == 0:
        _add(recs, "OK", "Nuclei n'a détecté aucune vulnérabilité connue sur ce site.")
        return risk

    critical = counts.get("critical", 0)
    high     = counts.get("high",     0)
    medium   = counts.get("medium",   0)
    low      = counts.get("low",      0)

    if critical > 0:
        risk += min(critical * 40, 50)
        _add(recs, "Critique",
             f"Nuclei a détecté {critical} vulnérabilité(s) CRITIQUE(S) nécessitant une correction immédiate. "
             f"Bilan complet : {high} haute(s), {medium} moyenne(s), {low} faible(s).")
    elif high > 0:
        risk += min(high * 20, 40)
        _add(recs, "Important", f"Nuclei a détecté {high} vulnérabilité(s) haute(s) et {medium} moyenne(s) sur ce site.")
    elif medium > 0:
        risk += min(medium * 10, 25)
        _add(recs, "Modéré", f"Nuclei a détecté {medium} vulnérabilité(s) de sévérité moyenne et {low} faible(s).")
    elif low > 0:
        risk += min(low * 3, 10)
        _add(recs, "Conseil", f"Nuclei a détecté {low} point(s) d'amélioration mineurs.")

    for sev_key in ("critical", "high", "medium", "low"):
        severity_label, _ = _NUCLEI_SEVERITY_MAP[sev_key]
        sev_findings      = [f for f in findings if f.get("severity") == sev_key]
        seen_names        = set()
        for finding in sev_findings:
            name        = finding.get("name_fr") or finding.get("name", "Vulnérabilité inconnue")
            description = finding.get("description", "")
            matched_at  = finding.get("matched_at",  "")
            cve_ids     = finding.get("cve_id",      [])
            cvss        = finding.get("cvss_score")
            if name in seen_names:
                continue
            seen_names.add(name)
            parts = [f"« {name} »"]
            if cve_ids:  parts.append(f"CVE : {', '.join(cve_ids)}")
            if cvss:     parts.append(f"Score CVSS : {cvss}")
            if matched_at and matched_at != finding.get("url", ""):
                parts.append(f"Localisation : {matched_at}")
            desc_short = (description[:200] + "…") if len(description) > 200 else description
            parts.append(f"➜ {desc_short or 'Consultez la documentation du modèle Nuclei pour corriger ce problème.'}")
            _add(recs, severity_label, " | ".join(parts))

    info_findings = [f for f in findings if f.get("severity") == "info"]
    if info_findings:
        seen_names = set()
        for finding in info_findings:
            name_fr     = finding.get("name_fr") or finding.get("name", "Information")
            desc_fr     = finding.get("description", "")
            matched_at  = finding.get("matched_at",  "")
            template_id = finding.get("template_id", "")
            if name_fr in seen_names:
                continue
            seen_names.add(name_fr)
            parts = [f"« {name_fr} »"]
            if matched_at: parts.append(f"Localisation : {matched_at}")
            desc_short = (desc_fr[:200] + "…") if len(desc_fr) > 200 else desc_fr
            parts.append(f"➜ {desc_short or (f'Modèle : {template_id}' if template_id else 'Aucun détail disponible.')}")
            _add(recs, "Info", " | ".join(parts))
    return risk


# ─── Orchestrateur ───────────────────────────────────────────────────────────

def _build_recommendations(report: dict) -> tuple[dict, int]:
    risk_score      = 0
    recommendations = {
        "headers": [], "ssl": [], "virustotal": [], "safe_browsing": [],
        "urlscan": [], "shodan": [], "wappalyzer": [], "zap": [], "nuclei": [],
    }
    risk_score += _build_headers_recs      (report.get("headers",       {}), recommendations["headers"])
    risk_score += _build_ssl_recs          (report.get("ssl",           {}), recommendations["ssl"])
    risk_score += _build_virustotal_recs   (report.get("virustotal",    {}), recommendations["virustotal"])
    risk_score += _build_safe_browsing_recs(report.get("safe_browsing", {}), recommendations["safe_browsing"])
    risk_score += _build_urlscan_recs      (report.get("urlscan",       {}), recommendations["urlscan"])
    risk_score += _build_shodan_recs       (report.get("shodan",        {}), recommendations["shodan"])
    risk_score += _build_wappalyzer_recs   (report.get("wappalyzer",   {}), recommendations["wappalyzer"])
    risk_score += _build_zap_recs          (report.get("zap",          {}), recommendations["zap"])
    risk_score += _build_nuclei_recs       (report.get("nuclei",       {}), recommendations["nuclei"])
    return recommendations, min(risk_score, 100)


def _build_display_report(report: dict, recommendations: dict, risk_score: int) -> dict:
    def _level(score: int) -> dict:
        if score >= 70: return {"label": "Élevé",   "color": "red",    "emoji": "🔴"}
        if score >= 40: return {"label": "Modéré",  "color": "orange", "emoji": "🟠"}
        if score >= 15: return {"label": "Faible",  "color": "yellow", "emoji": "🟡"}
        return                 {"label": "Minimal", "color": "green",  "emoji": "🟢"}

    level    = _level(risk_score)
    sections = {}
    for key, msgs in recommendations.items():
        label     = SECTION_LABELS.get(key, key)
        formatted = [_format_recommendation(m) for m in msgs]
        all_tags  = [_severity_from_tag(m) for m in msgs]
        if "Critique" in all_tags:                             section_status = "danger"
        elif "Important" in all_tags or "Alerte" in all_tags:  section_status = "warning"
        elif any(t in all_tags for t in ("Erreur", "Modéré")): section_status = "info"
        elif "OK" in all_tags:                                 section_status = "ok"
        else:                                                  section_status = "neutral"
        sections[key] = {"label": label, "status": section_status, "recommendations": formatted}

    return {
        "risk_score": risk_score,
        "risk_level": level,
        "sections":   sections,
        "summary":    _build_summary(risk_score, recommendations),
    }


def _build_summary(risk_score: int, recommendations: dict) -> str:
    critiques  = sum(1 for msgs in recommendations.values() for m in msgs if "[Critique]"  in m)
    importants = sum(1 for msgs in recommendations.values() for m in msgs if "[Important]" in m)
    if risk_score >= 70:
        return (f"Ce site présente {critiques} problème(s) critique(s). "
                "Il est fortement déconseillé de l'utiliser ou d'y saisir des informations personnelles.")
    if risk_score >= 40:
        return (f"Ce site présente {critiques + importants} problème(s) de sécurité notable(s). "
                "Soyez prudent et évitez de partager des mots de passe ou données bancaires ici.")
    if risk_score >= 15:
        return ("Ce site présente quelques points d'amélioration mineurs, "
                "mais il est globalement sûr pour un usage courant.")
    return ("Ce site ne présente aucun problème de sécurité connu. Vous pouvez l'utiliser en toute confiance.")


# ─── Tâche Celery ────────────────────────────────────────────────────────────

@celery_app.task(
    bind=True,
    soft_time_limit=800,
    time_limit=860,
    max_retries=1,
)
def scan_url_task(self, url: str, user_id: int, user_email: str):

    OUTILS = [
        ("headers",       "Protection du navigateur",        lambda: _safe_scan(scan_headers,           url, timeout=30)),
        ("ssl",           "Chiffrement HTTPS",               lambda: _scan_ssl_with_fallback(url)),
        ("virustotal",    "Antivirus VirusTotal",            lambda: _safe_scan(scan_virustotal,        url, timeout=60)),
        ("safe_browsing", "Google Safe Browsing",            lambda: _safe_scan(scan_safe_browsing,     url, timeout=30)),
        ("urlscan",       "Analyse comportementale urlscan", lambda: _safe_scan(scan_urlscan,           url, timeout=90)),
        ("shodan",        "Exposition serveur Shodan",       lambda: _safe_scan(scan_shodan_internetdb, url, timeout=30)),
        ("wappalyzer",    "Stack technologique Wappalyzer",  lambda: _safe_scan(scan_wappalyzer,        url, timeout=60)),
        ("zap",           "Vulnérabilités OWASP ZAP",        lambda: _safe_scan(scan_zap,               url, timeout=180)),
        ("nuclei",        "Vulnérabilités Nuclei",           lambda: _safe_scan(scan_nuclei,            url, timeout=360)),
    ]

    partial_results = {}
    raw_results     = {}
    total_outils    = len(OUTILS)

    self.update_state(
        state="PROGRESS",
        meta={
            "status":          "Démarrage de l'analyse...",
            "progress":        5,
            "current_tool":    None,
            "current_label":   None,
            "partial_results": {},
        }
    )

    for i, (key, label, fn) in enumerate(OUTILS):
        self.update_state(
            state="PROGRESS",
            meta={
                "status":          f"Analyse en cours : {label}...",
                "progress":        int(10 + (i / total_outils) * 75),
                "current_tool":    key,
                "current_label":   label,
                "partial_results": partial_results,
            }
        )
        try:
            raw = fn()
        except SoftTimeLimitExceeded:
            raise
        except Exception as exc:
            raw = {"status": "failed", "error": str(exc)}

        raw_results[key]     = raw
        partial_results[key] = _summarize_tool_result(key, raw)

    self.update_state(
        state="PROGRESS",
        meta={
            "status":          "Calcul du score de risque...",
            "progress":        88,
            "current_tool":    None,
            "current_label":   None,
            "partial_results": partial_results,
        }
    )

    recommendations, risk_score = _build_recommendations(raw_results)
    display_report              = _build_display_report(raw_results, recommendations, risk_score)
    all_recs_flat               = [rec for section in recommendations.values() for rec in section]

    full_report = {
        **raw_results,
        "risk_score":      risk_score,
        "recommendations": recommendations,
        "display":         display_report,
    }

    self.update_state(
        state="PROGRESS",
        meta={
            "status":          "Sauvegarde du rapport...",
            "progress":        98,
            "current_tool":    None,
            "current_label":   None,
            "partial_results": partial_results,
        }
    )

    db = SessionLocal()
    try:
        existing = db.query(Analysis).filter(
            Analysis.task_id == self.request.id
        ).first()

        if existing:

            existing.status          = "completed"
            existing.full_report     = full_report
            existing.summary         = {
                "grade":        raw_results.get("headers", {}).get("grade"),
                "risk":         risk_score,
                "risk_label":   display_report["risk_level"]["label"],
                "summary_text": display_report["summary"],
            }
            existing.risk_score      = risk_score
            existing.recommendations = "\n".join(all_recs_flat)
            db.commit()
        else:
            # Fallback : créer si introuvable
            repo = AnalysisRepository(db)
            repo.create_full(
                user_id         = user_id,
                user_email      = user_email,
                url             = url,
                status          = "completed",
                full_report     = full_report,
                summary         = {
                    "grade":        raw_results.get("headers", {}).get("grade"),
                    "risk":         risk_score,
                    "risk_label":   display_report["risk_level"]["label"],
                    "summary_text": display_report["summary"],
                },
                risk_score      = risk_score,
                recommendations = "\n".join(all_recs_flat),
                task_id         = self.request.id,
            )
    finally:
        db.close()

    return full_report