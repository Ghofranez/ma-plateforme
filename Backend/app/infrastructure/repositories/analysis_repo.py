from sqlalchemy.orm import Session
from app.core.entities.analysis import Analysis
import json

class AnalysisRepository:

    def __init__(self, db: Session):
        self.db = db

    def create(self, user_email: str, url: str, status: str, summary: dict):
        entry = Analysis(
            user_email=user_email,
            url=url,
            status=status,
            summary=json.dumps(summary)
        )
        self.db.add(entry)
        self.db.commit()
        return entry

    def get_by_user(self, user_email: str):
        return self.db.query(Analysis)\
            .filter(Analysis.user_email == user_email)\
            .order_by(Analysis.created_at.desc()).all()