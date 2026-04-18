from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from app.infrastructure.db.session import Base

class Analysis(Base):
    __tablename__ = "analyses"

    id         = Column(Integer, primary_key=True, index=True)
    user_email = Column(String(255), index=True)
    url        = Column(String(2048))
    status     = Column(String(50), default="completed")
    summary    = Column(String(5000), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)