from pydantic import BaseModel, EmailStr

# DTO pour inscription

class UserCreate(BaseModel):
    nom: str
    prenom: str
    cin: str
    email: EmailStr
    password: str
    confirm_password: str

# DTO pour login

class UserLogin(BaseModel):
    email: EmailStr
    password: str

# DTO pour demander un code par email

class EmailRequest(BaseModel):
    email: str

# DTO pour vérifier le code OTP lors du login

class VerifyLoginCode(BaseModel):
    email: str
    code: str

# DTO pour vérifier le code OTP lors du reset

class VerifyResetCode(BaseModel):
    email: str
    code: str

# DTO pour reset mot de passe

class ResetPassword(BaseModel):
    email: str
    code: str
    new_password: str

# DTO pour mise à jour du profil

class ProfileUpdate(BaseModel):
    nom: str
    prenom: str

# DTO pour changement de mot de passe

class ChangePassword(BaseModel):
    current_password: str
    new_password: str