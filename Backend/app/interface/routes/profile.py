from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from app.infrastructure.db.session import get_db
from app.infrastructure.repositories.user_repo import UserRepository
from app.middleware.auth_middleware import get_current_user
from app.core import security
from app.application.dto.auth_dto import ProfileUpdate, ChangePassword

router = APIRouter()

@router.get("/me")
def me(user_email: str = Depends(get_current_user), db: Session = Depends(get_db)):
    user = UserRepository(db).get_by_email(user_email)
    return {"nom": user.nom, "prenom": user.prenom, "email": user.email}

@router.put("/profil")
def update_profile(data: ProfileUpdate, user_email: str = Depends(get_current_user), db: Session = Depends(get_db)):
    UserRepository(db).update_profile(user_email, data.nom, data.prenom)
    return {"message": "Profil mis à jour"}

@router.put("/change-password")
def change_password(data: ChangePassword, user_email: str = Depends(get_current_user), db: Session = Depends(get_db)):
    repo = UserRepository(db)
    user = repo.get_by_email(user_email)
    if not security.verify_password(data.current_password, user.password):
        raise HTTPException(400, "Mot de passe incorrect")
    repo.update_password(user_email, data.new_password)
    return {"message": "Password changed"}

@router.post("/logout")
def logout(response: Response):
    response.delete_cookie("access_token")
    return {"message": "Déconnecté"}