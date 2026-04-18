import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.core.config import settings


def send_verification_email(email: str, code: str):
    """
    Envoie un email contenant le code OTP à l'utilisateur.
    Utilisé pour : login 2FA + reset mot de passe
    """

    msg = MIMEMultipart()
    msg["From"]    = settings.SMTP_EMAIL
    msg["To"]      = email
    msg["Subject"] = "Code de vérification"

    body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 400px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
        <h2 style="color: #333;">Vérification de votre compte</h2>
        <p>Voici votre code de vérification :</p>
        <div style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #4f46e5; text-align: center; padding: 20px;">
            {code}
        </div>
        <p style="color: #888; font-size: 13px;">Ce code expire dans <strong>10 minutes</strong>.</p>
        <p style="color: #888; font-size: 13px;">Si vous n'avez pas demandé ce code, ignorez cet email.</p>
    </div>
    """

    msg.attach(MIMEText(body, "html"))

    try:
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(settings.SMTP_EMAIL, settings.SMTP_PASSWORD)
        server.sendmail(settings.SMTP_EMAIL, email, msg.as_string())
        server.quit()
        print(f" Email envoyé à {email}")

    except smtplib.SMTPAuthenticationError:
        print("Erreur authentification Gmail — vérifie SMTP_EMAIL et SMTP_PASSWORD dans .env")

    except smtplib.SMTPException as e:
        print(f" Erreur SMTP : {e}")

    except Exception as e:
        print(f" Erreur inconnue : {e}")