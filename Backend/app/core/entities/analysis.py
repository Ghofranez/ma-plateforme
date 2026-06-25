import enum
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, func, ForeignKey, Enum
from sqlalchemy.orm import relationship
from app.infrastructure.db.session import Base


class AnalysisStatus(str, enum.Enum):
    processing = "processing"
    completed  = "completed"
    failed     = "failed"


class Analysis(Base):
    __tablename__ = "analyses"
    id              = Column(Integer, primary_key=True, index=True)
    user_id         = Column(Integer, ForeignKey("users.id"), index=True)
    surveillance_id = Column(Integer, ForeignKey("surveillances.id", ondelete="SET NULL"), nullable=True, index=True)
    url             = Column(String(2048))
    status          = Column(Enum(AnalysisStatus), default=AnalysisStatus.processing)
    created_at      = Column(DateTime, server_default=func.now())
    reference        = Column(String(255), nullable=True, index=True)
    full_report     = Column(JSON, nullable=True)
    summary         = Column(JSON, nullable=True)
    risk_score      = Column(Integer, default=0)
    recommendations = Column(Text, nullable=True)

    user         = relationship("User", back_populates="analyses")
    surveillance = relationship("Surveillance", back_populates="analyses")