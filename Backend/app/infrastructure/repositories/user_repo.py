from sqlalchemy.orm import Session
from app.core.entities.user import User
from app.core.security import hash_password

class UserRepository:

    def __init__(self, db: Session):
        self.db = db

    def get_by_email(self, email: str):
        return self.db.query(User).filter(User.email == email).first()

    def create(self, nom, prenom, cin, email, password):
        user = User(
            nom=nom, prenom=prenom, cin=cin,
            email=email, password=hash_password(password)
        )
        self.db.add(user)
        self.db.commit()
        return user

    def update_profile(self, email: str, nom: str, prenom: str):
        user = self.get_by_email(email)
        user.nom = nom
        user.prenom = prenom
        self.db.commit()

    def update_password(self, email: str, new_password: str):
        user = self.get_by_email(email)
        user.password = hash_password(new_password)
        self.db.commit()