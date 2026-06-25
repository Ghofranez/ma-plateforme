# surveillance_repo.py
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.core.entities.surveillance import Surveillance

class SurveillanceRepository:
    def __init__(self, db: Session):
        self.db = db

    def activer(self, user_id: int, url: str) -> Surveillance:
     from app.core.entities.analysis import Analysis
     now = datetime.utcnow()
     last_analysis = (
        self.db.query(Analysis)
        .filter(
            Analysis.user_id == user_id,
            Analysis.url     == url,
            Analysis.status  == "completed",
        )
        .order_by(Analysis.created_at.desc())
        .first()
     )
     surveil = Surveillance(
         user_id      = user_id,
         url          = url,
         active       = True,
         last_scan_at = None,
         next_scan_at = now + timedelta(hours=24),
         last_rapport = last_analysis.full_report if last_analysis else None,
     )
     self.db.add(surveil)
     self.db.commit()
     self.db.refresh(surveil)
     return surveil

    def desactiver(self, user_id: int, url: str) -> None:
        self.db.query(Surveillance).filter(
            Surveillance.user_id == user_id,
            Surveillance.url     == url,
            Surveillance.active  == True,
        ).delete()
        self.db.commit()

    # ── Lecture ───────────────────────────────────────────────────────────
    def get_by_id(self, surveillance_id: int) -> Surveillance | None:
        return self.db.query(Surveillance).filter(
            Surveillance.id == surveillance_id,
        ).first()

    def get_status(self, user_id: int, url: str) -> Surveillance | None:
        return self.db.query(Surveillance).filter(
            Surveillance.user_id == user_id,
            Surveillance.url     == url,
            Surveillance.active  == True,
        ).first()

    def get_all_active_by_user(self, user_id: int) -> list[Surveillance]:
        return self.db.query(Surveillance).filter(
            Surveillance.user_id == user_id,
            Surveillance.active  == True,
        ).all()

    def get_all_active(self) -> list[Surveillance]:
        return self.db.query(Surveillance).filter(
            Surveillance.active == True,
        ).all()

    # ── Mise à jour après scan ────────────────────────────────────────────
    def marquer_scannee(self, surveil, prochaine_heures: int):
        now = datetime.utcnow()
        surveil.last_scan_at = now
        surveil.next_scan_at = now + timedelta(hours=prochaine_heures)
        self.db.commit()