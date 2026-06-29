from sqlalchemy.orm import Session
from app.core.entities.user import User
from app.core.security import hash_password

class UserRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_email(self, email: str):
        return self.db.query(User).filter(User.email == email).first()

    def get_by_id(self, user_id: int):
        return self.db.query(User).filter(User.id == user_id).first()

    def create(self, nom, prenom, phone, email, password):
        user = User(
            nom=nom, prenom=prenom, phone=phone if phone else None,
            email=email, password=hash_password(password)
        )
        self.db.add(user)
        self.db.commit()
        return user

    def update_profile(self, email: str, nom: str, prenom: str, phone: str =None):
        user = self.get_by_email(email)
        user.nom    = nom
        user.prenom = prenom
        if phone :
            user.phone = phone
        self.db.commit()

    def update_password(self, email: str, new_password: str):
        user = self.get_by_email(email)
        user.password = hash_password(new_password)
        self.db.commit()

    # ──  cherche par ancien email ────────────────────────────────
    def update_email_by_email(self, old_email: str, new_email: str):


        user = self.get_by_email(old_email)
        if not user:
            from fastapi import HTTPException
            raise HTTPException(404, "Utilisateur non trouvé")

        user.email = new_email
        self.db.commit()
        return user