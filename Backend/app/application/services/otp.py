from datetime import datetime, timedelta, timezone  # ← ajoute timezone
from app.application.services.email import send_verification_email
import random, string

email_verification = {}
reset_verification  = {}
last_sent           = {}

def _now():
    return datetime.now(timezone.utc)  # ← fonction utilitaire

def generate_code() -> str:
    return ''.join(random.SystemRandom().choices(string.digits, k=6))

def store_login_code(email: str):
    code = generate_code()
    email_verification[email] = {
        "code": code,
        "expires": _now() + timedelta(minutes=10)
    }
    send_verification_email(email, code)

def verify_login_code(email: str, code: str) -> bool:
    session = email_verification.get(email)
    if not session: return False
    if session["expires"] < _now(): return False
    if session["code"] != code: return False
    email_verification.pop(email, None)
    return True

def store_reset_code(email: str):
    code = generate_code()
    reset_verification[email] = {
        "code": code,
        "expires": _now() + timedelta(minutes=10)
    }
    send_verification_email(email, code)

def verify_reset_code(email: str, code: str) -> bool:
    session = reset_verification.get(email)
    if not session: return False
    if session["expires"] < _now(): return False
    if session["code"] != code: return False
    return True

def clear_reset_code(email: str):
    reset_verification.pop(email, None)

def check_cooldown(email: str) -> bool:
    last = last_sent.get(email)
    if last and (_now() - last).seconds < 30:
        return False
    last_sent[email] = _now()
    return True