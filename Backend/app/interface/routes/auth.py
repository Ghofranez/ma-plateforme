from fastapi import APIRouter, Depends, Response, HTTPException
from sqlalchemy.orm import Session
from app.infrastructure.db.session import get_db
from app.infrastructure.repositories.user_repo import UserRepository
from app.domain.use_cases.auth_cases import AuthUseCases
from app.core.security import create_access_token, set_auth_cookie
from app.application.dto.auth_dto import (
    UserCreate, UserLogin, EmailRequest,
    VerifyLoginCode, VerifyResetCode, ResetPassword
)
from app.application.services import otp

router = APIRouter()

def get_use_case(db: Session = Depends(get_db)):
    return AuthUseCases(UserRepository(db))

@router.post("/register")
def register(user: UserCreate, uc: AuthUseCases = Depends(get_use_case)):
    return uc.register(user.nom, user.prenom, user.cin, user.email, user.password, user.confirm_password)

@router.post("/login")
def login(user: UserLogin, uc: AuthUseCases = Depends(get_use_case)):
    return uc.login(user.email, user.password)

@router.post("/send-email-code")
def send_email_code(data: EmailRequest, db: Session = Depends(get_db)):
    repo = UserRepository(db)
    if not repo.get_by_email(data.email):
        from fastapi import HTTPException
        raise HTTPException(404, "User not found")
    if not otp.check_cooldown(data.email):
        from fastapi import HTTPException
        raise HTTPException(429, "Veuillez attendre avant de renvoyer")
    otp.store_login_code(data.email)
    return {"message": "Code sent"}

# ── verify-login-code — envoie le token dans un cookie ──
@router.post("/verify-login-code")
def verify_login_code(
    data: VerifyLoginCode,
    response: Response,           # ← ajouter Response
    uc: AuthUseCases = Depends(get_use_case)
):
    if not otp.verify_login_code(data.email, data.code):
        raise HTTPException(400, "Code invalide ou expiré")

    token = create_access_token({"sub": data.email})
    set_auth_cookie(response, token)  # ← stocke dans cookie

    return {"message": "Login successful"}

@router.post("/forgot-password")
def forgot_password(data: EmailRequest, uc: AuthUseCases = Depends(get_use_case)):
    return uc.forgot_password(data.email)

@router.post("/verify-reset-code")
def verify_reset_code(data: VerifyResetCode, uc: AuthUseCases = Depends(get_use_case)):
    return uc.verify_reset(data.email, data.code)

@router.post("/reset-password")
def reset_password(data: ResetPassword, uc: AuthUseCases = Depends(get_use_case)):
    return uc.reset_password(data.email, data.code, data.new_password)