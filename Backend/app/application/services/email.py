import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.core.config import settings

# ─── URL Frontend ─────────────────────────────────────────────────────────────

FRONTEND_URL = "http://localhost:3000"


# ─── Email vérification OTP ───────────────────────────────────────────────────

def send_verification_email(email: str, code: str):
    msg = MIMEMultipart()
    msg["From"]    = settings.SMTP_EMAIL
    msg["To"]      = email
    msg["Subject"] = "Code de vérification"

    body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 400px; margin: auto; padding: 20px;
                border: 1px solid #eee; border-radius: 10px;">
        <h2 style="color: #333;">Vérification de votre compte</h2>
        <p>Voici votre code de vérification :</p>
        <div style="font-size: 32px; font-weight: bold; letter-spacing: 8px;
                    color: #4f46e5; text-align: center; padding: 20px;">
            {code}
        </div>
        <p style="color: #888; font-size: 13px;">Ce code expire dans <strong>10 minutes</strong>.</p>
        <p style="color: #888; font-size: 13px;">Si vous n'avez pas demandé ce code, ignorez cet email.</p>
    </div>
    """

    msg.attach(MIMEText(body, "html"))
    _send(msg, email)


# ─── Helpers internes ─────────────────────────────────────────────────────────

def _send(msg, to_email: str):
    """Envoie un email via Gmail SMTP SSL."""
    try:
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(settings.SMTP_EMAIL, settings.SMTP_PASSWORD)
        server.sendmail(settings.SMTP_EMAIL, to_email, msg.as_string())
        server.quit()
        print(f"Email envoyé à {to_email}")
    except smtplib.SMTPAuthenticationError:
        print("Erreur authentification Gmail — vérifiez SMTP_EMAIL et SMTP_PASSWORD")
    except smtplib.SMTPException as e:
        print(f"Erreur SMTP : {e}")
    except Exception as e:
        print(f"Erreur inconnue : {e}")


def _severity_badge(severity: str) -> str:
    colors = {
        "CRITICAL": "#dc2626",
        "HIGH":     "#ea580c",
        "MEDIUM":   "#ca8a04",
        "LOW":      "#6b7280",
    }
    color = colors.get(severity, "#6b7280")
    return (
        f'<span style="background:{color};color:white;padding:2px 8px;'
        f'border-radius:4px;font-size:12px;font-weight:bold;">{severity}</span>'
    )


def _rec_icon(msg: str) -> str:
    if "[Critique]"  in msg: return "#dc2626"
    if "[Important]" in msg: return "#ea580c"
    if "[Modéré]"    in msg: return "#ca8a04"
    if "[OK]"        in msg: return "#16a34a"
    if "[Erreur]"    in msg: return "#dc2626"
    return "#6b7280"


def _format_rec_html(rec: str) -> str:
    clean = re.sub(r"^\[.+?\]\s*", "", rec)
    color = _rec_icon(rec)
    return (
        f'<li style="margin-bottom:8px;padding:10px;background:#f9fafb;'
        f'border-left:3px solid {color};border-radius:4px;'
        f'font-size:13px;color:#374151;">{clean}</li>'
    )


def _build_rapport_link(analysis_id) -> str:
    """
    Construit le bouton lien vers le rapport.
    """
    if not analysis_id:
        return ""

    # Le lien direct : Next.js gère la protection + redirect
    rapport_url = f"{FRONTEND_URL}/surveillance/rapport/{analysis_id}"

    return f"""
    <div style="margin-top:20px;text-align:center;">
      <a href="{rapport_url}"
         style="display:inline-block;background:#1e3a5f;color:white;
                padding:12px 28px;border-radius:6px;text-decoration:none;
                font-size:14px;font-weight:bold;letter-spacing:0.3px;">
        Voir le rapport complet
      </a>
      <p style="margin-top:8px;color:#9ca3af;font-size:11px;">
        Vous serez invité à vous connecter si ce n'est pas déjà fait.
      </p>
    </div>
    """


# ─── Alerte anomalie — scan léger et rapide ───────────────────────────────────

def send_anomaly_alert(
    to_email: str,
    url: str,
    anomalies: list[dict],
    recommendations: dict | None = None,
    scan_type: str = "léger",
    analysis_id=None,                   # ← ID du rapport Analysis sauvegardé
):
    # ── Lien rapport ──
    lien_html = _build_rapport_link(analysis_id)

    # ── Tableau anomalies ──
    rows_html = ""
    for a in anomalies:
        rows_html += f"""
        <tr>
          <td style="padding:10px;border-bottom:1px solid #e5e7eb;vertical-align:top;">
            {_severity_badge(a['severity'])}
          </td>
          <td style="padding:10px;border-bottom:1px solid #e5e7eb;color:#374151;font-size:14px;">
            {a['message']}
          </td>
        </tr>
        """

    # ── Section recommandations (si fournies) ──
    recs_html = ""
    if recommendations:
        SECTION_LABELS = {
            "headers":       "Protection du navigateur",
            "ssl":           "Chiffrement HTTPS",
            "virustotal":    "Antivirus (VirusTotal)",
            "safe_browsing": "Google Safe Browsing",
            "urlscan":       "Analyse comportementale",
            "shodan":        "Exposition serveur (Shodan)",
            "wappalyzer":    "Stack technologique",
            "zap":           "Vulnérabilités web (ZAP)",
            "nuclei":        "Vulnérabilités ciblées (Nuclei)",
        }

        sections_html = ""
        for key, recs in recommendations.items():
            important_recs = [
                r for r in recs
                if any(tag in r for tag in ["[Critique]", "[Important]", "[Modéré]", "[Erreur]", "[Alerte]"])
            ]
            if not important_recs:
                continue
            label = SECTION_LABELS.get(key, key)
            items = "".join(_format_rec_html(r) for r in important_recs)
            sections_html += f"""
            <div style="margin-bottom:20px;">
                <h4 style="color:#1e3a5f;margin:0 0 8px;font-size:14px;
                           text-transform:uppercase;letter-spacing:0.5px;">
                    {label}
                </h4>
                <ul style="margin:0;padding-left:0;list-style:none;">
                    {items}
                </ul>
            </div>
            """

        if sections_html:
            recs_html = f"""
            <h3 style="color:#111827;margin-top:28px;border-top:1px solid #e5e7eb;padding-top:20px;">
                Recommandations pour corriger ces problèmes
            </h3>
            {sections_html}
            """

    # ── Badge type de scan ──
    scan_badges = {
        "léger":   ("#6366f1", "Scan léger (1h)"),
        "rapide":  ("#0891b2", "Scan rapide (24h)"),
        "complet": ("#059669", "Scan complet (72h)"),
    }
    scan_color, scan_label = scan_badges.get(scan_type, ("#6b7280", scan_type))

    body = f"""
    <div style="font-family:Arial,sans-serif;max-width:650px;margin:auto;
                border:1px solid #eee;border-radius:10px;overflow:hidden;">

      <!-- Header -->
      <div style="background:#1e3a5f;padding:24px;color:white;">
        <div style="display:flex;align-items:center;justify-content:space-between;">
          <div>
            <h2 style="margin:0;font-size:20px;"> Alerte de Surveillance</h2>
            <p style="margin:4px 0 0;opacity:.8;font-size:13px;">
              Anomalie(s) détectée(s) sur votre URL surveillée
            </p>
          </div>
          <span style="background:{scan_color};color:white;padding:4px 12px;
                       border-radius:20px;font-size:12px;font-weight:bold;white-space:nowrap;">
            {scan_label}
          </span>
        </div>
      </div>

      <!-- Body -->
      <div style="padding:24px;">

        <p style="color:#374151;margin-top:0;">
          Des changements suspects ont été détectés sur :
        </p>
        <div style="background:#f3f4f6;padding:12px;border-radius:6px;
                    font-family:monospace;word-break:break-all;color:#1e3a5f;font-size:14px;">
          {url}
        </div>

        <!-- Anomalies -->
        <h3 style="color:#111827;margin-top:24px;">
          {len(anomalies)} anomalie(s) détectée(s)
        </h3>
        <table style="width:100%;border-collapse:collapse;font-size:14px;">
          <thead>
            <tr style="background:#f9fafb;">
              <th style="padding:10px;text-align:left;color:#6b7280;
                         font-size:11px;text-transform:uppercase;width:120px;">Sévérité</th>
              <th style="padding:10px;text-align:left;color:#6b7280;
                         font-size:11px;text-transform:uppercase;">Détail</th>
            </tr>
          </thead>
          <tbody>{rows_html}</tbody>
        </table>

        <!-- Recommandations -->
        {recs_html}

        <!-- Bouton rapport -->
        {lien_html}

        <!-- Note si pas de lien -->
        {'' if analysis_id else '''
        <div style="margin-top:24px;padding:16px;background:#fef3c7;
                    border-left:4px solid #f59e0b;border-radius:4px;">
          <p style="margin:0;color:#92400e;font-size:14px;">
            Connectez-vous pour consulter votre historique et appliquer les corrections.
          </p>
        </div>
        '''}

      </div>

      <!-- Footer -->
      <div style="padding:16px 24px;background:#f9fafb;
                  text-align:center;color:#9ca3af;font-size:12px;">
        Email automatique — Plateforme de surveillance de sécurité
      </div>
    </div>
    """

    msg = MIMEMultipart()
    msg["From"]    = settings.SMTP_EMAIL
    msg["To"]      = to_email
    msg["Subject"] = f" [{len(anomalies)} anomalie(s)] Alerte {scan_type} — {url[:50]}"
    msg.attach(MIMEText(body, "html"))
    _send(msg, to_email)


# ─── Email scan complet — rapport complet avec anomalies ─────────────────────

def send_scan_complet_alert(
    to_email: str,
    url: str,
    anomalies: list[dict],
    recommendations: dict,
    risk_score: int,
    risk_label: str,
    analysis_id=None,
):
    # Couleur score
    if risk_score >= 70:   score_color = "#dc2626"
    elif risk_score >= 40: score_color = "#ea580c"
    elif risk_score >= 15: score_color = "#ca8a04"
    else:                  score_color = "#16a34a"

    # Lien rapport
    lien_html = _build_rapport_link(analysis_id)

    # Anomalies
    rows_html = ""
    for a in anomalies:
        rows_html += f"""
        <tr>
          <td style="padding:10px;border-bottom:1px solid #e5e7eb;vertical-align:top;">
            {_severity_badge(a['severity'])}
          </td>
          <td style="padding:10px;border-bottom:1px solid #e5e7eb;color:#374151;font-size:14px;">
            {a['message']}
          </td>
        </tr>
        """

    # Recommandations importantes
    SECTION_LABELS = {
        "headers":       "Protection du navigateur",
        "ssl":           "Chiffrement HTTPS",
        "virustotal":    "Antivirus (VirusTotal)",
        "safe_browsing": "Google Safe Browsing",
        "urlscan":       "Analyse comportementale",
        "shodan":        "Exposition serveur (Shodan)",
        "wappalyzer":    "Stack technologique",
        "zap":           "Vulnérabilités web (ZAP)",
        "nuclei":        "Vulnérabilités ciblées (Nuclei)",
    }

    sections_html = ""
    for key, recs in recommendations.items():
        important_recs = [
            r for r in recs
            if any(tag in r for tag in ["[Critique]", "[Important]", "[Modéré]", "[Erreur]"])
        ]
        if not important_recs:
            continue
        label = SECTION_LABELS.get(key, key)
        items = "".join(_format_rec_html(r) for r in important_recs)
        sections_html += f"""
        <div style="margin-bottom:20px;">
            <h4 style="color:#1e3a5f;margin:0 0 8px;font-size:14px;
                       text-transform:uppercase;letter-spacing:0.5px;">{label}</h4>
            <ul style="margin:0;padding-left:0;list-style:none;">{items}</ul>
        </div>
        """

    body = f"""
    <div style="font-family:Arial,sans-serif;max-width:650px;margin:auto;
                border:1px solid #eee;border-radius:10px;overflow:hidden;">

      <!-- Header -->
      <div style="background:#1e3a5f;padding:24px;color:white;">
        <h2 style="margin:0;font-size:20px;"> Rapport de scan complet</h2>
        <p style="margin:4px 0 0;opacity:.8;font-size:13px;">
          Analyse automatique complète — {len(anomalies)} anomalie(s) détectée(s)
        </p>
      </div>

      <!-- Body -->
      <div style="padding:24px;">

        <!-- URL -->
        <p style="color:#374151;margin-top:0;">URL analysée :</p>
        <div style="background:#f3f4f6;padding:12px;border-radius:6px;
                    font-family:monospace;word-break:break-all;color:#1e3a5f;font-size:14px;">
          {url}
        </div>

        <!-- Score -->
        <div style="margin-top:20px;text-align:center;padding:20px;
                    background:#f9fafb;border-radius:8px;">
          <p style="margin:0;color:#6b7280;font-size:13px;">Score de risque</p>
          <p style="margin:8px 0 0;font-size:48px;font-weight:bold;color:{score_color};">
            {risk_score}%
          </p>
          <span style="background:{score_color};color:white;padding:4px 16px;
                       border-radius:20px;font-size:13px;font-weight:bold;">
            {risk_label}
          </span>
        </div>

        <!-- Anomalies -->
        <h3 style="color:#111827;margin-top:24px;">Anomalies détectées</h3>
        <table style="width:100%;border-collapse:collapse;font-size:14px;">
          <thead>
            <tr style="background:#f9fafb;">
              <th style="padding:10px;text-align:left;color:#6b7280;
                         font-size:11px;text-transform:uppercase;width:120px;">Sévérité</th>
              <th style="padding:10px;text-align:left;color:#6b7280;
                         font-size:11px;text-transform:uppercase;">Détail</th>
            </tr>
          </thead>
          <tbody>{rows_html}</tbody>
        </table>

        <!-- Recommandations -->
        {"<h3 style='color:#111827;margin-top:28px;border-top:1px solid #e5e7eb;padding-top:20px;'>Recommandations pour corriger ces problèmes</h3>" + sections_html if sections_html else ""}

        <!-- Bouton rapport -->
        {lien_html}

      </div>

      <!-- Footer -->
      <div style="padding:16px 24px;background:#f9fafb;
                  text-align:center;color:#9ca3af;font-size:12px;">
        Email automatique — Plateforme de surveillance de sécurité
      </div>
    </div>
    """

    msg = MIMEMultipart()
    msg["From"]    = settings.SMTP_EMAIL
    msg["To"]      = to_email
    msg["Subject"] = f" Rapport complet [{risk_score}% risque] — {url[:50]}"
    msg.attach(MIMEText(body, "html"))
    _send(msg, to_email)


# ─── Email confirmation — scan terminé sans anomalie ─────────────────────────

def send_scan_ok_alert(
    to_email: str,
    url: str,
    scan_type: str,
    risk_score: int | None = None,
):
    scan_badges = {
        "rapide (24h)": ("#0891b2", "Scan rapide (24h)"),
        "complet":      ("#059669", "Scan complet (72h)"),
    }
    scan_color, scan_label = scan_badges.get(scan_type, ("#6b7280", scan_type))

    score_block = ""
    if risk_score is not None:
        if risk_score >= 70:   score_color = "#dc2626"
        elif risk_score >= 40: score_color = "#ea580c"
        elif risk_score >= 15: score_color = "#ca8a04"
        else:                  score_color = "#16a34a"

        score_block = f"""
        <div style="margin-top:20px;text-align:center;padding:20px;
                    background:#f9fafb;border-radius:8px;">
          <p style="margin:0;color:#6b7280;font-size:13px;">Score de risque actuel</p>
          <p style="margin:8px 0 0;font-size:48px;font-weight:bold;color:{score_color};">
            {risk_score}%
          </p>
        </div>
        """

    body = f"""
    <div style="font-family:Arial,sans-serif;max-width:650px;margin:auto;
                border:1px solid #eee;border-radius:10px;overflow:hidden;">

      <!-- Header -->
      <div style="background:#1e3a5f;padding:24px;color:white;">
        <div style="display:flex;align-items:center;justify-content:space-between;">
          <div>
            <h2 style="margin:0;font-size:20px;"> Scan terminé — Aucune anomalie</h2>
            <p style="margin:4px 0 0;opacity:.8;font-size:13px;">
              Votre URL est saine
            </p>
          </div>
          <span style="background:{scan_color};color:white;padding:4px 12px;
                       border-radius:20px;font-size:12px;font-weight:bold;white-space:nowrap;">
            {scan_label}
          </span>
        </div>
      </div>

      <!-- Body -->
      <div style="padding:24px;">

        <p style="color:#374151;margin-top:0;">URL analysée :</p>
        <div style="background:#f3f4f6;padding:12px;border-radius:6px;
                    font-family:monospace;word-break:break-all;
                    color:#1e3a5f;font-size:14px;">
          {url}
        </div>

        {score_block}

        <!-- Résultat -->
        <div style="margin-top:20px;padding:16px;background:#f0fdf4;
                    border-left:4px solid #16a34a;border-radius:4px;">
          <p style="margin:0;color:#166534;font-size:14px;">
            Aucune anomalie détectée lors de ce scan.
            Votre site est conforme aux critères de sécurité vérifiés.
          </p>
        </div>

      </div>

      <!-- Footer -->
      <div style="padding:16px 24px;background:#f9fafb;
                  text-align:center;color:#9ca3af;font-size:12px;">
        Email automatique — Plateforme de surveillance de sécurité
      </div>
    </div>
    """

    msg = MIMEMultipart()
    msg["From"]    = settings.SMTP_EMAIL
    msg["To"]      = to_email
    msg["Subject"] = f"Scan {scan_type} terminé — Aucune anomalie — {url[:50]}"
    msg.attach(MIMEText(body, "html"))
    _send(msg, to_email)

# ─── Confirmation changement email ───────────────────────────────────────────

def send_email_change_confirmation(old_email: str, new_email: str, token: str):
    confirm_url = f"{FRONTEND_URL}/confirm-email?token={token}"

    body = f"""
    <div style="font-family:Arial,sans-serif;max-width:500px;margin:auto;
                border:1px solid #eee;border-radius:10px;overflow:hidden;">

      <!-- Header -->
      <div style="background:#1e3a5f;padding:24px;color:white;">
        <h2 style="margin:0;font-size:20px;"> Confirmation de changement d'email</h2>
        <p style="margin:4px 0 0;opacity:.8;font-size:13px;">
          Une demande de modification a été effectuée
        </p>
      </div>

      <!-- Body -->
      <div style="padding:24px;">

        <p style="color:#374151;margin-top:0;">
          Vous avez demandé à changer votre adresse email vers :
        </p>

        <div style="background:#f3f4f6;padding:12px;border-radius:6px;
                    font-family:monospace;color:#1e3a5f;font-size:14px;">
          {new_email}
        </div>

        <p style="color:#374151;margin-top:20px;">
          Cliquez sur le bouton ci-dessous pour confirmer ce changement.
          Ce lien est valable <strong>30 minutes</strong>.
        </p>

        <div style="margin-top:20px;text-align:center;">
          <a href="{confirm_url}"
             style="display:inline-block;background:#4f46e5;color:white;
                    padding:12px 28px;border-radius:6px;text-decoration:none;
                    font-size:14px;font-weight:bold;">
            Confirmer le changement
          </a>
        </div>

        <!-- Avertissement -->
        <div style="margin-top:24px;padding:14px;background:#fef3c7;
                    border-left:4px solid #f59e0b;border-radius:4px;">
          <p style="margin:0;color:#92400e;font-size:13px;">
             Si vous n'êtes pas à l'origine de cette demande,
            ignorez cet email. Votre adresse actuelle reste inchangée.
          </p>
        </div>

      </div>

      <!-- Footer -->
      <div style="padding:16px 24px;background:#f9fafb;
                  text-align:center;color:#9ca3af;font-size:12px;">
        Email automatique — Plateforme de surveillance de sécurité
      </div>
    </div>
    """

    msg = MIMEMultipart()
    msg["From"]    = settings.SMTP_EMAIL
    msg["To"]      = old_email
    msg["Subject"] = "Confirmation de changement d'email"
    msg.attach(MIMEText(body, "html"))
    _send(msg, old_email)