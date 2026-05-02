# config.py — Variables d'environnement
# Pydantic BaseSettings lit automatiquement les variables d'environnement
# et le fichier .env

from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Base de données
    DATABASE_URL: str

    # Sécurité
    SECRET_KEY: str
    ALGORITHM: str           = "HS256"
    TOKEN_EXPIRE_MINUTES: int = 60

    # Email
    SMTP_EMAIL:    str = ""
    SMTP_PASSWORD: str = ""

    # Redis
    REDIS_URL: str = ""

    # APIs outils de sécurité
    VIRUSTOTAL_KEY:           str = ""
    GOOGLE_SAFE_BROWSING_KEY: str = ""
    URLSCAN_API_KEY:          str = ""
    OPENPHISH_ENABLED:        str = "true"

    class Config:
        env_file =  ".env"          # lit le fichier .env automatiquement
        extra    = "ignore"         # ignore les variables inconnues sans erreur

    def validate_required(self):
        """Appelle cette méthode au démarrage de l'app pour vérifier les clés critiques."""
        if not self.DATABASE_URL:
            raise ValueError("DATABASE_URL manquante !")
        if not self.SECRET_KEY:
            raise ValueError("SECRET_KEY manquante !")


settings = Settings()