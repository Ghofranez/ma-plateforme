from fastapi import Cookie, HTTPException
from app.core.security import decode_access_token

# Middleware pour récupérer l’utilisateur courant via le cookie JWT
def get_current_user(access_token: str = Cookie(None)) -> str:
    if not access_token:
        raise HTTPException(status_code=401, detail="Non autorisé")

    payload = decode_access_token(access_token)

    if not payload:
        raise HTTPException(status_code=401, detail="Token invalide")

    return payload.get("sub") #retourne l'email de l'utilisateur

