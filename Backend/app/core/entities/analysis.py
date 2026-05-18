from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, func, Boolean, ForeignKey
from datetime import datetime
from app.infrastructure.db.session import Base

class Analysis(Base):
    __tablename__ = "analyses"
    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"), index=True)
    user_email = Column(String(255), index=True)
    url        = Column(String(2048))
    status     = Column(String(50), default="processing")
    created_at = Column(DateTime, server_default=func.now())
    task_id    = Column(String(255), nullable=True, index=True)
    full_report     = Column(JSON, nullable=True)
    summary         = Column(JSON, nullable=True)
    risk_score      = Column(Integer, default=0)
    recommendations = Column(Text, nullable=True)
    