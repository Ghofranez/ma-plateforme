from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from app.infrastructure.db.session import get_db
from app.infrastructure.repositories.user_repo import UserRepository
from app.middleware.auth_middleware import get_current_user
from app.core import security
from app.application.dto.auth_dto import ProfileUpdate, ChangePassword, ChangeEmail
from app.core.entities.user import User

router = APIRouter()

@router.get("/me")
def me(current_user: User = Depends(get_current_user)):
    return {
        "nom":    current_user.nom,
        "prenom": current_user.prenom,
        "email":  current_user.email,
    }

@router.put("/profil")
def update_profile(
    data:         ProfileUpdate,
    current_user: User    = Depends(get_current_user),
    db:           Session = Depends(get_db),
):
    UserRepository(db).update_profile(current_user.email, data.nom, data.prenom)
    return {"message": "Profil mis à jour"}

@router.put("/change-password")
def change_password(
    data:         ChangePassword,
    current_user: User    = Depends(get_current_user),
    db:           Session = Depends(get_db),
):
    if not security.verify_password(data.current_password, current_user.password):
        raise HTTPException(400, "Mot de passe incorrect")
    UserRepository(db).update_password(current_user.email, data.new_password)
    return {"message": "Password changed"}

@router.post("/logout")
def logout(response: Response):
    response.delete_cookie("access_token")
    return {"message": "Déconnecté"}
@router.put("/change-email")
def change_email(
    data:         ChangeEmail,
    current_user: User     = Depends(get_current_user),
    db:           Session  = Depends(get_db),
    response:     Response = None,
):
    repo = UserRepository(db)

    # Vérifier mot de passe
    if not security.verify_password(data.password, current_user.password):
        raise HTTPException(400, "Mot de passe incorrect")

    # Vérifier que le nouvel email n'est pas déjà pris
    if repo.get_by_email(data.new_email):
        raise HTTPException(400, "Cet email est déjà utilisé")

    # Changer l'email partout
    repo.update_email(current_user.id, data.new_email)

    # Supprimer le cookie → forcer reconnexion
    response.delete_cookie("access_token")

    return {"message": "Email modifié, veuillez vous reconnecter"}