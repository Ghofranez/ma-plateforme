import re
from fastapi import HTTPException
from app.core import security
from app.application.services import otp


class AuthUseCases:
    def __init__(self, user_repo):
        self.user_repo = user_repo

    def _validate_password(self, password: str):
        """Règles de sécurité pour le mot de passe"""
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
        self._validate_password(password)  # ← validation ajoutée
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
        return {"message": "Mot de passe modifié"}