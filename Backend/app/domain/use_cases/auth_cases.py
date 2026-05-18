import re
import secrets
from datetime import datetime, timedelta
from fastapi import HTTPException
from app.core import security
from app.application.services import otp

# Stockage temporaire des tokens 
email_change_tokens: dict = {}

class AuthUseCases:
    def __init__(self, user_repo):
        self.user_repo = user_repo

    def _validate_password(self, password: str):
        if len(password) < 8:
            raise HTTPException(400, "Le mot de passe doit contenir au moins 8 caractères")
        if not re.search(r'[A-Z]', password):
            raise HTTPException(400, "Le mot de passe doit contenir au moins une majuscule")
        if not re.search(r'[0-9]', password):
            raise HTTPException(400, "Le mot de passe doit contenir au moins un chiffre")
        if not re.search(r'[!@#$%^&*(),.?]', password):
            raise HTTPException(400, "Le mot de passe doit contenir au moins un caractère spécial")

    def register(self, nom, prenom, cin, email, password, confirm_password):
        if password != confirm_password:
            raise HTTPException(400, "Passwords mismatch")
        self._validate_password(password)
        if self.user_repo.get_by_email(email):
            raise HTTPException(400, "Email already used")
        self.user_repo.create(nom, prenom, cin, email, password)
        return {"message": "User created"}

    def login(self, email, password):
        user = self.user_repo.get_by_email(email)
        if not user or not security.verify_password(password, user.password):
            raise HTTPException(401, "Invalid credentials")
        otp.store_login_code(email)
        return {"requires2FA": True, "email": email}

    def verify_login(self, email, code):
        if not otp.verify_login_code(email, code):
            raise HTTPException(400, "Code invalide ou expiré")
        token = security.create_access_token({"sub": email})
        return {"access_token": token}

    def forgot_password(self, email):
        if not self.user_repo.get_by_email(email):
            raise HTTPException(404, "Utilisateur non trouvé")
        otp.store_reset_code(email)
        return {"message": "Code envoyé"}

    def verify_reset(self, email, code):
        if not otp.verify_reset_code(email, code):
            raise HTTPException(400, "Code invalide ou expiré")
        return {"message": "Code valide"}

    def reset_password(self, email, code, new_password):
        if not otp.verify_reset_code(email, code):
            raise HTTPException(400, "Code invalide ou expiré")
        self._validate_password(new_password)
        self.user_repo.update_password(email, new_password)
        otp.clear_reset_code(email)

        # notifier l'utilisateur
        from app.application.services.email import send_password_changed_notification
        send_password_changed_notification(email)

        return {"message": "Mot de passe modifié"}

    # ──  changement email sécurisé ──────────────────────────────

    def request_email_change(self, current_user_email: str, new_email: str, password: str):
        user = self.user_repo.get_by_email(current_user_email)
        if not user:
            raise HTTPException(404, "Utilisateur non trouvé")

        if not security.verify_password(password, user.password):
            raise HTTPException(400, "Mot de passe incorrect")

        if self.user_repo.get_by_email(new_email):
            raise HTTPException(400, "Cet email est déjà utilisé")

        token = secrets.token_urlsafe(32)
        email_change_tokens[token] = {
            "user_email": current_user_email,
            "new_email":  new_email,
            "expires_at": datetime.now() + timedelta(minutes=30)
        }

        otp.notify_email_change(
            old_email=current_user_email,
            new_email=new_email,
            token=token
        )

        return {"message": "Email de confirmation envoyé à votre adresse actuelle"}

    def confirm_email_change(self, token: str):
        data = email_change_tokens.get(token)

        if not data:
            raise HTTPException(400, "Token invalide")

        if datetime.now() > data["expires_at"]:
            del email_change_tokens[token]
            raise HTTPException(400, "Token expiré, refaites la demande")

        # update_email prend l'ancien email (on cherche par email dans repo)
        self.user_repo.update_email_by_email(data["user_email"], data["new_email"])
        del email_change_tokens[token]

        return {"message": "Email modifié avec succès, veuillez vous reconnecter"}