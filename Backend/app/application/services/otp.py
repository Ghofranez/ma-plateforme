import redis
import random
import string
from app.core.config import settings
from app.application.services.email import (
    send_verification_email,
    send_email_change_confirmation as send_email_change_confirmation_email  
)

def get_redis():
    return redis.from_url(settings.REDIS_URL, decode_responses=True)

def generate_code() -> str:
    return ''.join(random.SystemRandom().choices(string.digits, k=6))

# ── LOGIN 2FA ──────────────────────────────────────────────────────────────
def store_login_code(email: str):
    r = get_redis()
    code = generate_code()
    r.setex(f"otp:login:{email}", 600, code)
    send_verification_email(email, code)

def verify_login_code(email: str, code: str) -> bool:
    r = get_redis()
    stored = r.get(f"otp:login:{email}")
    if not stored or stored != code:
        return False
    r.delete(f"otp:login:{email}")
    return True

# ── RESET MOT DE PASSE ─────────────────────────────────────────────────────
def store_reset_code(email: str):
    r = get_redis()
    code = generate_code()
    r.setex(f"otp:reset:{email}", 600, code)
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

# ── ANTI-SPAM ──────────────────────────────────────────────────────────────
def check_cooldown(email: str) -> bool:
    r = get_redis()
    key = f"otp:cooldown:{email}"
    if r.exists(key):
        return False
    r.setex(key, 30, "1")
    return True

# ── confirmation changement email ────────────────────────────────
def notify_email_change(old_email: str, new_email: str, token: str):
    # Appelle la fonction d'email.py (avec l'alias pour éviter la récursion)
    send_email_change_confirmation_email(
        old_email=old_email,
        new_email=new_email,
        token=token
    )