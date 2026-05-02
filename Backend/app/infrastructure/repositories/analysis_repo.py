from sqlalchemy.orm import Session
from app.core.entities.analysis import Analysis
import json


class AnalysisRepository:
    def __init__(self, db: Session):
        self.db = db

    def create_full(
        self,
        user_email: str,
        url: str,
        status: str,
        full_report,
        summary,
        risk_score: int = 0,
        recommendations: str = "",
        has_changes: int = 0,
        changes_summary: str = ""
    ):
        entry = Analysis(
            user_email      = user_email,
            url             = url,
            status          = status,
            full_report     = full_report if isinstance(full_report, str) else json.dumps(full_report),
            summary         = summary if isinstance(summary, str) else json.dumps(summary),
            risk_score      = risk_score,
            recommendations = recommendations,
            has_changes     = has_changes,
            changes_summary = changes_summary,
        )
        self.db.add(entry)
        self.db.commit()
        self.db.refresh(entry)
        return entry

    def get_by_user(self, user_email: str):
        """Récupère toutes les analyses d'un utilisateur, du plus récent au plus ancien"""
        return self.db.query(Analysis)\
            .filter(Analysis.user_email == user_email)\
            .order_by(Analysis.created_at.desc())\
            .all()

    def get_by_id(self, analysis_id: int):
        """Récupère une analyse par son ID"""
        return self.db.query(Analysis)\
            .filter(Analysis.id == analysis_id)\
            .first()

    def delete(self, analysis_id: int) -> bool:
        """Supprime une analyse par son ID"""
        entry = self.get_by_id(analysis_id)
        if not entry:
            return False
        self.db.delete(entry)
        self.db.commit()
        return True

    def get_last_by_url(self, user_email: str, url: str):
        """Pour comparaison avec l'analyse précédente de la même URL"""
        return self.db.query(Analysis)\
            .filter(
                Analysis.user_email == user_email,
                Analysis.url == url
            )\
            .order_by(Analysis.created_at.desc())\
            .first()