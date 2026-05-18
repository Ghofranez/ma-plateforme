from fastapi import Cookie, HTTPException, Depends
from sqlalchemy.orm import Session
from app.core.security import decode_access_token
from app.infrastructure.db.session import get_db
from app.core.entities.user import User

def get_current_user(
    access_token: str     = Cookie(None),
    db:           Session = Depends(get_db),
) -> User:
    if not access_token:
        raise HTTPException(status_code=401, detail="Non autorisé")

    payload = decode_access_token(access_token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token invalide")

    email = payload.get("sub")
    user  = db.query(User).filter(User.email == email).first()

    if not user:
        raise HTTPException(status_code=401, detail="Utilisateur introuvable")

    return user