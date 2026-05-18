from fastapi      import APIRouter, Depends
from sqlalchemy.orm import Session
from datetime     import datetime, timedelta

from app.infrastructure.db.session                 import get_db
from app.infrastructure.repositories.analysis_repo import AnalysisRepository
from app.application.services.celery_app           import celery_app
from app.middleware.auth_middleware                 import get_current_user
from app.core.entities.user                        import User

router = APIRouter(prefix="/tasks", tags=["Tasks"])

@router.get("/en-cours")
def get_active_tasks(
    current_user: User    = Depends(get_current_user),
    db:           Session = Depends(get_db),
):
    repo   = AnalysisRepository(db)
    cutoff = datetime.utcnow() - timedelta(hours=2)
    active = repo.get_active_by_user(user_id=current_user.id, since=cutoff)

    result = []
    for analysis in active:
        task          = celery_app.AsyncResult(analysis.task_id)
        celery_status = task.state
        if celery_status in ("SUCCESS", "FAILURE"):
            continue
        result.append({
            "taskId":   analysis.task_id,
            "url":      analysis.url,
            "status":   "running" if celery_status == "PROGRESS" else "pending",
            "progress": (task.info or {}).get("status", "En cours...") if celery_status == "PROGRESS" else "Démarrage...",
        })

    return {"tasks": result}