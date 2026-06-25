import enum
from sqlalchemy import Column, Integer, String, Enum
from sqlalchemy.orm import relationship
from app.infrastructure.db.session import Base


class UserRole(str, enum.Enum):
    user  = "user"
    admin = "admin"


class User(Base):
    __tablename__ = "users"
    id       = Column(Integer, primary_key=True, index=True)
    nom      = Column(String(100))
    prenom   = Column(String(100))
    phone    = Column(String(8), unique=True)
    email    = Column(String(255), unique=True)
    password = Column(String(255))
    role     = Column(Enum(UserRole), default=UserRole.user)

    analyses      = relationship("Analysis", back_populates="user")
    surveillances = relationship("Surveillance", back_populates="user")