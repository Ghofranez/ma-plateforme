 #variables d'environnement
import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    DATABASE_URL: str        = os.getenv("DATABASE_URL")
    SECRET_KEY: str          = os.getenv("SECRET_KEY")
    ALGORITHM: str           = "HS256"
    TOKEN_EXPIRE_MINUTES: int = 60
    SMTP_EMAIL: str          = os.getenv("SMTP_EMAIL")
    SMTP_PASSWORD: str       = os.getenv("SMTP_PASSWORD")
    #VIRUSTOTAL_KEY: str      = os.getenv("VIRUSTOTAL_KEY")
    #ZAP_API_KEY: str         = os.getenv("ZAP_API_KEY", "changeme")
    #WAPPALYZER_KEY: str      = os.getenv("WAPPALYZER_KEY")
    #IPQS_KEY: str            = os.getenv("IPQS_KEY")


def validate(self):
        if not self.DATABASE_URL:
            raise ValueError("DATABASE_URL manquante !")
        if not self.SECRET_KEY:
            raise ValueError("SECRET_KEY manquante !")
settings = Settings()