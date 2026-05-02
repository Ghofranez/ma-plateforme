import jwt
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    to_encode["exp"] = datetime.now(timezone.utc) + timedelta(minutes=settings.TOKEN_EXPIRE_MINUTES)
    token = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return token if isinstance(token, str) else token.decode("utf-8")

def decode_access_token(token: str):
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

from fastapi import Response

# Cookie HttpOnly = JavaScript ne peut pas le lire
# → protège contre les attaques XSS

def set_auth_cookie(response: Response, token: str):
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,       # ← JavaScript ne peut pas lire
        secure=True,        # ← True en production (HTTPS)
        samesite="lax",      # ← protection CSRF
        max_age=3600,        # ← expire dans 1h (secondes)
    )