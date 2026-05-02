import redis
import random
import string
from app.core.config import settings
from app.application.services.email import send_verification_email

# Connexion Redis — même URL que Celery dans ton .env
def get_redis():
    return redis.from_url(settings.REDIS_URL, decode_responses=True)


def generate_code() -> str:
    # Génère un code à 6 chiffres aléatoires
    return ''.join(random.SystemRandom().choices(string.digits, k=6))


# ── LOGIN 2FA ──────────────────────────────────────────────────────────────
def store_login_code(email: str):
    r= get_redis()
    code = generate_code()
    r.setex(f"otp:login:{email}", 600, code)  # expire automatiquement en 10 min
    send_verification_email(email, code)


def verify_login_code(email: str, code: str) -> bool:
    r = get_redis()
    stored = r.get(f"otp:login:{email}")
    if not stored or stored != code:
        return False
    r.delete(f"otp:login:{email}")  # supprimer après usage (code à usage unique)
    return True


# ── RESET MOT DE PASSE ─────────────────────────────────────────────────────
def store_reset_code(email: str):
    r = get_redis()
    code = generate_code()
    r.setex(f"otp:reset:{email}", 600, code)  # expire automatiquement en 10 min
    send_verification_email(email, code)


def verify_reset_code(email: str, code: str) -> bool:
    r = get_redis()
    stored = r.get(f"otp:reset:{email}")
    if not stored or stored != code:
        return False
    return True


def clear_reset_code(email: str):
    r = get_redis()
    r.delete(f"otp:reset:{email}")


# ── ANTI-SPAM : cooldown 30 secondes entre deux envois ─────────────────────
def check_cooldown(email: str) -> bool:
    r = get_redis()
    key = f"otp:cooldown:{email}"
    if r.exists(key):
        return False  # encore en cooldown
    r.setex(key, 30, "1")  # bloquer pendant 30 secondes
    return True