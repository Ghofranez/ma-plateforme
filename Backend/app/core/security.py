import jwt
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from fastapi import Response, Request, HTTPException, Depends
from sqlalchemy.orm import Session
from app.core.config import settings
from app.infrastructure.db.session import get_db

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

def set_auth_cookie(response: Response, token: str):
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=settings.TOKEN_EXPIRE_MINUTES * 60,
    )

# ──récupère l'utilisateur connecté depuis le cookie ────────────
def get_current_user(request: Request, db: Session = Depends(get_db)):
    from app.infrastructure.repositories.user_repo import UserRepository

    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(401, "Non authentifié")

    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(401, "Token invalide ou expiré")

    email = payload.get("sub")
    if not email:
        raise HTTPException(401, "Token invalide")

    user = UserRepository(db).get_by_email(email)
    if not user:
        raise HTTPException(404, "Utilisateur non trouvé")

    return user