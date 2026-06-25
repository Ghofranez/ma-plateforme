# surveillance_task.py

import json
import logging
import socket

from datetime import datetime
from celery import shared_task
from app.infrastructure.db.session import SessionLocal
from app.infrastructure.repositories.surveillance_repo import SurveillanceRepository
from app.application.services.email import (
    send_anomaly_alert,
    send_scan_complet_alert,
    send_scan_ok_alert,
)

from app.application.services.tools.security_headers import scan_headers
from app.application.services.tools.ssl_labs         import scan_ssl
from app.application.services.tools.testssl          import scan_testssl
from app.application.services.tools.virustotal       import scan_virustotal
from app.application.services.tools.safe_browsing    import scan_safe_browsing
from app.application.services.tools.urlscan          import scan_urlscan
from app.application.services.tools.shodan           import scan_shodan_internetdb
from app.application.services.tools.availability     import check_availability

logger = logging.getLogger(__name__)

ANOMALY_RULES = {
    "risk_score_delta":   20,
    "malicious_verdicts": ["malicious", "phishing", "malware"],
    "critical_headers":   ["Strict-Transport-Security", "Content-Security-Policy"],
    "ssl_expiry_days":    14,
}


# ─── Utilitaires ──────────────────────────────────────────────────────────────

def _resolve_ip(url: str) -> str | None:
    try:
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname
        return socket.gethostbyname(hostname) if hostname else None
    except Exception:
        return None


def _safe_run(fn, *args):
    try:
        return fn(*args)
    except Exception as exc:
        return {"status": "failed", "error": str(exc)}


_NO_FALLBACK_ERROR_TYPES = {"rate_limit", "timeout", "network"}


def _scan_ssl_with_fallback(url: str) -> dict:
    result = _safe_run(scan_ssl, url)
    if result.get("status") == "completed":
        result["_source"]       = "ssllabs"
        result["fallback_used"] = False
        return result
    if result.get("error_type", "") in _NO_FALLBACK_ERROR_TYPES:
        result.setdefault("_source", "ssllabs")
        result["fallback_used"] = False
        return result
    fallback = _safe_run(scan_testssl, url)
    fallback["_source"]       = "python_ssl"
    fallback["fallback_used"] = True
    return fallback


def url_est_prete_a_scanner(surveil) -> bool:
    maintenant = datetime.utcnow()

    if surveil.last_scan_at is None:
        return (maintenant - surveil.created_at).total_seconds() >= 86400

    return (maintenant - surveil.last_scan_at).total_seconds() >= 86400

def _parse_old_rapport(surveil) -> dict:
    old = surveil.last_rapport or {}
    if isinstance(old, str):
        try:
            return json.loads(old)
        except Exception:
            return {}
    return old


def _sauvegarder_analysis(db, surveil, new_rapport, anomalies,
                           risk_score=None, recommendations=None,
                           display_report=None) -> int | None:
    from app.core.entities.analysis import Analysis

    summary_data = {
        "is_auto_scan": True,
        "scan_type":    "complet",
        "anomalies":    len(anomalies),
    }
    if risk_score is not None:
        summary_data["risk"] = risk_score
    if display_report:
        summary_data["risk_label"]   = display_report.get("risk_level", {}).get("label", "")
        summary_data["summary_text"] = display_report.get("summary", "")

    full_report_to_save = {**new_rapport}
    if risk_score is not None:
        full_report_to_save["risk_score"] = risk_score
    if recommendations:
        full_report_to_save["recommendations"] = recommendations
    if display_report:
        full_report_to_save["display"] = display_report

    try:
        analyse = Analysis(
            user_id         = surveil.user_id,
            url             = surveil.url,
            status          = "completed",
            risk_score      = risk_score,
            full_report     = full_report_to_save,
            summary         = json.dumps(summary_data),
            recommendations = (
                "\n".join(
                    rec
                    for section in recommendations.values()
                    for rec in section
                )
                if recommendations else None
            ),
        )
        db.add(analyse)
        db.commit()
        db.refresh(analyse)
        logger.info(f"[SURVEILLANCE] Analysis #{analyse.id} sauvegardée pour {surveil.url}")
        return analyse.id
    except Exception as e:
        logger.error(f"[SURVEILLANCE] Erreur sauvegarde {surveil.url} : {e}")
        db.rollback()
        return None


def _run_scan_complet(url: str) -> dict:
    from app.application.services.scanner import run_full_scan
    rapport = run_full_scan(url)
    rapport["availability"] = _safe_run(check_availability, url)
    return rapport


# ─── Détection d'anomalies ────────────────────────────────────────────────────

def detect_anomalies(old_data: dict, new_data: dict) -> list[dict]:
    anomalies = []

    old_avail = old_data.get("availability", {})
    new_avail = new_data.get("availability", {})
    if old_avail.get("is_up") is True and new_avail.get("is_up") is False:
        anomalies.append({
            "type":     "AVAILABILITY",
            "severity": "CRITICAL",
            "message":  "Site inaccessible — était UP lors du dernier scan.",
        })

    old_score = old_data.get("risk_score") or 0
    new_score = new_data.get("risk_score") or 0
    delta     = new_score - old_score
    if delta >= ANOMALY_RULES["risk_score_delta"]:
        anomalies.append({
            "type":     "RISK_SCORE",
            "severity": "HIGH",
            "message":  f"Score de risque : {old_score} → {new_score} (+{delta} pts)",
        })

    old_vt = old_data.get("virustotal", {}).get("malicious", 0) or 0
    new_vt = new_data.get("virustotal", {}).get("malicious", 0) or 0
    if new_vt > 0 and old_vt == 0:
        anomalies.append({
            "type":     "VIRUSTOTAL",
            "severity": "CRITICAL",
            "message":  f"{new_vt} antivirus signalent ce site comme dangereux (VirusTotal).",
        })

    old_sb = old_data.get("safe_browsing", {})
    new_sb = new_data.get("safe_browsing", {})
    if old_sb.get("safe") is True and new_sb.get("safe") is False:
        threats = new_sb.get("threats", [])
        anomalies.append({
            "type":     "SAFE_BROWSING",
            "severity": "CRITICAL",
            "message":  f"Google Safe Browsing signale ce site comme dangereux. Menaces : {', '.join(threats)}",
        })

    old_headers = set(old_data.get("headers", {}).get("present", []))
    new_headers = set(new_data.get("headers", {}).get("present", []))
    for header in ANOMALY_RULES["critical_headers"]:
        if header in old_headers and header not in new_headers:
            anomalies.append({
                "type":     "MISSING_HEADER",
                "severity": "MEDIUM",
                "message":  f"Header de sécurité supprimé : {header}",
            })

    ssl_days = new_data.get("ssl", {}).get("cert", {}).get("daysRemaining")
    if ssl_days is not None and ssl_days <= ANOMALY_RULES["ssl_expiry_days"]:
        anomalies.append({
            "type":     "SSL_EXPIRY",
            "severity": "HIGH",
            "message":  f"Certificat SSL expire dans {ssl_days} jours.",
        })

    old_malicious = (old_data.get("urlscan", {}).get("verdict") or {}).get("malicious", False)
    new_malicious = (new_data.get("urlscan", {}).get("verdict") or {}).get("malicious", False)
    if new_malicious and not old_malicious:
        anomalies.append({
            "type":     "URLSCAN_MALICIOUS",
            "severity": "CRITICAL",
            "message":  "urlscan.io détecte un comportement malveillant sur ce site.",
        })

    old_risky = set(old_data.get("shodan", {}).get("riskyPorts", []))
    new_risky = set(new_data.get("shodan", {}).get("riskyPorts", []))
    nouveaux  = new_risky - old_risky
    if nouveaux:
        anomalies.append({
            "type":     "RISKY_PORT",
            "severity": "HIGH",
            "message":  f"Nouveau(x) port(s) dangereux détecté(s) : {', '.join(str(p) for p in nouveaux)}",
        })

    # ── Wappalyzer ────────────────────────────────────────────────────────
    old_wap       = old_data.get("wappalyzer", {})
    new_wap       = new_data.get("wappalyzer", {})
    old_risky_wap = {t["name"] for t in (old_wap.get("risk_technologies") or [])}
    new_risky_wap = {t["name"] for t in (new_wap.get("risk_technologies") or [])}
    nouveaux_wap  = new_risky_wap - old_risky_wap

    if nouveaux_wap:
        anomalies.append({
            "type":     "WAPPALYZER_RISKY_TECH",
            "severity": "HIGH",
            "message":  f"Nouvelle(s) technologie(s) risquée(s) détectée(s) : "
                        f"{', '.join(nouveaux_wap)}.",
        })

    # Vérification phpMyAdmin apparu
    old_tech_names = {t["name"].lower() for t in (old_wap.get("technologies") or [])}
    new_tech_names = {t["name"].lower() for t in (new_wap.get("technologies") or [])}
    if "phpmyadmin" in new_tech_names and "phpmyadmin" not in old_tech_names:
        anomalies.append({
            "type":     "WAPPALYZER_PHPMYADMIN",
            "severity": "CRITICAL",
            "message":  "phpMyAdmin est apparu publiquement sur ce site — "
                        "accès base de données exposé.",
        })

    # ── ZAP ───────────────────────────────────────────────────────────────
    old_zap      = old_data.get("zap", {})
    new_zap      = new_data.get("zap", {})
    old_counts_z = (old_zap.get("alerts") or {}).get("counts", {})
    new_counts_z = (new_zap.get("alerts") or {}).get("counts", {})
    old_high_z   = old_counts_z.get("high",   0)
    new_high_z   = new_counts_z.get("high",   0)
    old_medium_z = old_counts_z.get("medium", 0)
    new_medium_z = new_counts_z.get("medium", 0)

    if new_high_z > old_high_z:
        anomalies.append({
            "type":     "ZAP_HIGH",
            "severity": "CRITICAL",
            "message":  f"OWASP ZAP : {new_high_z} vulnérabilité(s) critique(s) "
                        f"(était {old_high_z}).",
        })

    if new_medium_z > old_medium_z:
        anomalies.append({
            "type":     "ZAP_MEDIUM",
            "severity": "HIGH",
            "message":  f"OWASP ZAP : {new_medium_z} vulnérabilité(s) importante(s) "
                        f"(était {old_medium_z}).",
        })

    # ── Nuclei ────────────────────────────────────────────────────────────
    old_nuclei     = old_data.get("nuclei", {})
    new_nuclei     = new_data.get("nuclei", {})

    if new_nuclei.get("partial"):
        anomalies.append({
            "type":     "NUCLEI_PARTIAL",
            "severity": "MEDIUM",
            "message":  "Le scan Nuclei n'a pas pu se terminer entièrement dans le délai imparti — "
                        "les résultats de cette vérification sont incomplets.",
        })

    old_counts_n   = old_nuclei.get("counts") or {}
    new_counts_n   = new_nuclei.get("counts") or {}
    old_critical_n = old_counts_n.get("critical", 0)
    new_critical_n = new_counts_n.get("critical", 0)
    old_high_n     = old_counts_n.get("high",     0)
    new_high_n     = new_counts_n.get("high",     0)
    old_medium_n   = old_counts_n.get("medium",   0)
    new_medium_n   = new_counts_n.get("medium",   0)

    if new_critical_n > old_critical_n:
        anomalies.append({
            "type":     "NUCLEI_CRITICAL",
            "severity": "CRITICAL",
            "message":  f"Nuclei : {new_critical_n} vulnérabilité(s) critique(s) "
                        f"(était {old_critical_n}).",
        })

    if new_high_n > old_high_n:
        anomalies.append({
            "type":     "NUCLEI_HIGH",
            "severity": "HIGH",
            "message":  f"Nuclei : {new_high_n} vulnérabilité(s) haute(s) "
                        f"(était {old_high_n}).",
        })

    if new_medium_n > old_medium_n:
        anomalies.append({
            "type":     "NUCLEI_MEDIUM",
            "severity": "MEDIUM",
            "message":  f"Nuclei : {new_medium_n} vulnérabilité(s) moyenne(s) "
                        f"(était {old_medium_n}).",
        })

    return anomalies



# ─── Traitement scan complet ──────────────────────────────────────────────────

def _process_complet(surveil, new_rapport: dict, db):
    from app.application.services.tasks import _build_recommendations, _build_display_report

    repo        = SurveillanceRepository(db)
    old_rapport = _parse_old_rapport(surveil)
    anomalies   = detect_anomalies(old_rapport, new_rapport) if old_rapport else []

    try:
        recommendations, risk_score = _build_recommendations(new_rapport)
        display_report              = _build_display_report(new_rapport, recommendations, risk_score)
    except Exception as e:
        logger.error(f"[SURVEILLANCE] Erreur build recommendations : {e}")
        recommendations = {}
        risk_score      = 0
        display_report  = {"risk_level": {"label": "Inconnu"}, "summary": ""}

    # ── TOUJOURS sauvegarder le rapport ──────────────────────────────
    analysis_id = _sauvegarder_analysis(
        db              = db,
        surveil         = surveil,
        new_rapport     = new_rapport,
        anomalies       = anomalies,
        risk_score      = risk_score,
        recommendations = recommendations,
        display_report  = display_report,
    )
    if analysis_id:
        db.commit()

    # ── Envoi email selon résultat ────────────────────────────────────
    if not anomalies:
        logger.info(f"[SURVEILLANCE] Aucun changement pour {surveil.url}")
        send_scan_ok_alert(
            to_email   = surveil.user.email,
            url        = surveil.url,
            scan_type  = "complet (24h)",
            risk_score = risk_score,
            analysis_id= analysis_id,
        )
    else:
        logger.warning(f"[SURVEILLANCE] {len(anomalies)} anomalie(s) sur {surveil.url}")
        send_scan_complet_alert(
            to_email        = surveil.user.email,
            url             = surveil.url,
            anomalies       = anomalies,
            recommendations = recommendations,
            risk_score      = risk_score,
            risk_label      = display_report["risk_level"]["label"],
            analysis_id     = analysis_id,
        )

    surveil.last_rapport = new_rapport
    surveil.last_scan_at = datetime.utcnow()
    repo.marquer_scannee(surveil, prochaine_heures=24)

# ─── TÂCHE BEAT : dispatcher uniquement ───────────────────────────────────────

@shared_task(
    name="app.application.services.surveillance_task.scan_complet_toutes_urls"
)
def scan_complet_toutes_urls():

    db = SessionLocal()
    try:
        repo        = SurveillanceRepository(db)
        toutes      = repo.get_all_active()
        urls_pretes = [u for u in toutes if url_est_prete_a_scanner(u)]

        logger.info(f"[BEAT] {len(urls_pretes)}/{len(toutes)} URLs prêtes — dispatch en cours")

        for i, surveil in enumerate(urls_pretes):
            nb_urls   = len(urls_pretes)
            espacement = 60 if nb_urls > 20 else 30 if nb_urls > 10 else 15
            countdown  = i * espacement

            logger.info(
                 f"[BEAT] {nb_urls} URLs — espacement {espacement}s entre chaque scan"
            )
            scan_une_url.apply_async(
                args      = [surveil.id],
                countdown = countdown,
            )
            logger.info(
                f"[BEAT] Dispatch #{i+1} → surveillance id={surveil.id} "
                f"url={surveil.url} dans {countdown}s"
            )
    finally:
        db.close()


# ─── TÂCHE INDIVIDUELLE : scanne une seule URL ────────────────────────────────

@shared_task(
    name               = "app.application.services.surveillance_task.scan_une_url",
    bind               = True,
    max_retries        = 2,
    default_retry_delay= 300,  # retry après 5 min si échec
    soft_time_limit    = 1800, #  max par URL
    time_limit         = 1860, #kill aprés
)
def scan_une_url(self, surveillance_id: int):

    db = SessionLocal()
    try:
        repo    = SurveillanceRepository(db)
        surveil = repo.get_by_id(surveillance_id)

        if not surveil:
            logger.warning(f"[SCAN] Surveillance #{surveillance_id} introuvable, skip")
            return

        if not surveil.active:
            logger.info(f"[SCAN] Surveillance #{surveillance_id} désactivée entre-temps, skip")
            return

        # Double-check : évite un double-scan si la tâche a été rejouée
        if not url_est_prete_a_scanner(surveil):
            logger.info(f"[SCAN] {surveil.url} déjà scannée récemment, skip")
            return

        logger.info(f"[SCAN] Début scan complet → {surveil.url}")
        new_rapport = _run_scan_complet(surveil.url)
        _process_complet(surveil, new_rapport, db)
        logger.info(f"[SCAN] Terminé → {surveil.url}")

    except Exception as exc:
        logger.error(f"[SCAN] Erreur surveillance #{surveillance_id} : {exc}")
        raise self.retry(exc=exc)
    finally:
        db.close()


# ─── TÂCHE UPTIME : toutes les 5 minutes ──────────────────────────────────────

@shared_task(
    name="app.application.services.surveillance_task.scan_uptime_toutes_urls"
)
def scan_uptime_toutes_urls():
    """
    Tourne toutes les 5 minutes (Beat).
    Vérifie uniquement la disponibilité — alerte immédiate si site DOWN.
    """
    db = SessionLocal()
    try:
        repo   = SurveillanceRepository(db)
        toutes = repo.get_all_active()

        for surveil in toutes:
            try:
                result = _safe_run(check_availability, surveil.url)
                if not result.get("is_up"):
                    logger.warning(f"[UPTIME] Site DOWN : {surveil.url}")
                    send_anomaly_alert(
                        to_email  = surveil.user.email,
                        url       = surveil.url,
                        anomalies = [{
                            "type":     "AVAILABILITY",
                            "severity": "CRITICAL",
                            "message":  "Site inaccessible détecté (vérification uptime 5min).",
                        }],
                    )
            except Exception as e:
                logger.error(f"[UPTIME] Erreur {surveil.url} : {e}")
    finally:
        db.close()