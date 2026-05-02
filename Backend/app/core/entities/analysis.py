from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, func
from datetime import datetime
from app.infrastructure.db.session import Base

class Analysis(Base):
    __tablename__ = "analyses"

    id         = Column(Integer, primary_key=True, index=True)
    user_email = Column(String(255), index=True)
    url        = Column(String(2048))
    status     = Column(String(50), default="processing")
    created_at = Column(DateTime, server_default=func.now())
    summary = Column(Text, nullable=True)

    # ── Rapport complet ────────────────────────────────
    full_report = Column(JSON, nullable=True)

    # ── Score global ───────────────────────────────────
    risk_score       = Column(Integer, default=0)

    # ── Recommandations ────────────────────────────────
    recommendations  = Column(Text, nullable=True)

    # ── Comparaison analyse précédente ─────────────────
    has_changes      = Column(Integer, default=0)
    changes_summary  = Column(Text, nullable=True)