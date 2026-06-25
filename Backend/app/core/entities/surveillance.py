# models/surveillance.py
from sqlalchemy import Column, Integer, String, Boolean, DateTime, JSON, func, ForeignKey
from sqlalchemy.orm import relationship
from app.infrastructure.db.session import Base

class Surveillance(Base):
    __tablename__ = "surveillances"

    id           = Column(Integer, primary_key=True, index=True)
    user_id      = Column(Integer, ForeignKey("users.id"), index=True)
    url          = Column(String(2048))
    active       = Column(Boolean, default=True)
    last_rapport = Column(JSON, nullable=True)
    last_scan_at = Column(DateTime, nullable=True)
    next_scan_at = Column(DateTime, nullable=True)
    created_at   = Column(DateTime, server_default=func.now())

    user     = relationship("User", back_populates="surveillances")
    analyses = relationship("Analysis", back_populates="surveillance", passive_deletes=True)