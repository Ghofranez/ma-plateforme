from sqlalchemy.orm import Session
from app.core.entities.analysis import Analysis
from datetime import datetime

class AnalysisRepository:
    def __init__(self, db: Session):
        self.db = db

    def create_full(
        self,
        user_id: int,
        user_email: str,
        url: str,
        status: str,
        full_report,
        summary,
        risk_score: int = 0,
        recommendations: str = "",
        task_id: str = None,

    ):
        entry = Analysis(
            user_id         = user_id,
            user_email      = user_email,
            url             = url,
            status          = status,
            full_report     = full_report,
            summary         = summary,
            risk_score      = risk_score,
            recommendations = recommendations,
            task_id         = task_id,
        )
        self.db.add(entry)
        self.db.commit()
        self.db.refresh(entry)
        return entry

    def get_by_user(self, user_id: int):
        return self.db.query(Analysis)\
            .filter(Analysis.user_id == user_id)\
            .order_by(Analysis.created_at.desc())\
            .all()

    def get_by_id(self, analysis_id: int):
        return self.db.query(Analysis)\
            .filter(Analysis.id == analysis_id)\
            .first()

    def delete(self, analysis_id: int) -> bool:
        entry = self.get_by_id(analysis_id)
        if not entry:
            return False
        self.db.delete(entry)
        self.db.commit()
        return True

    def get_last_by_url(self, user_id: int, url: str):
        return self.db.query(Analysis)\
            .filter(
                Analysis.user_id == user_id,
                Analysis.url     == url,
            )\
            .order_by(Analysis.created_at.desc())\
            .first()

    def get_active_by_user(self, user_id: int, since: datetime):
        return self.db.query(Analysis)\
            .filter(
                Analysis.user_id == user_id,
                Analysis.status.in_(["pending", "running"]),
                Analysis.created_at >= since,
            )\
            .order_by(Analysis.created_at.desc())\
            .all()