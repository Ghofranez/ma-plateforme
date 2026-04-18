from sqlalchemy import Column, Integer, String
from app.infrastructure.db.session import Base

class User(Base):
    __tablename__ = "users"

    id       = Column(Integer, primary_key=True, index=True)
    nom      = Column(String(100))
    prenom   = Column(String(100))
    cin      = Column(String(255), unique=True)
    email    = Column(String(255), unique=True)
    password = Column(String(255))