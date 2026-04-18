from pydantic import BaseModel, EmailStr

class UserCreate(BaseModel):
    nom: str
    prenom: str
    cin: str
    email: EmailStr
    password: str
    confirm_password: str

class UserLogin(BaseModel):
    email: str
    password: str

class EmailRequest(BaseModel):
    email: str

class VerifyLoginCode(BaseModel):
    email: str
    code: str

class VerifyResetCode(BaseModel):
    email: str
    code: str

class ResetPassword(BaseModel):
    email: str
    code: str
    new_password: str

class ProfileUpdate(BaseModel):
    nom: str
    prenom: str

class ChangePassword(BaseModel):
    current_password: str
    new_password: str