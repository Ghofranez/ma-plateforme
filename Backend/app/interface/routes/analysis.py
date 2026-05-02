import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from celery.result import AsyncResult

from app.infrastructure.db.session import get_db
from app.infrastructure.repositories.analysis_repo import AnalysisRepository
from app.domain.use_cases.analysis_cases import AnalysisUseCases
from app.middleware.auth_middleware import get_current_user
from app.application.dto.analysis_dto import UrlAnalyze
from app.application.services.tasks import scan_url_task
from app.application.services.celery_app import celery_app
from app.core.entities.analysis import Analysis
from app.application.services.delete import delete_history_item

router = APIRouter()


def get_use_case(db: Session = Depends(get_db)):
    return AnalysisUseCases(AnalysisRepository(db))


# ── Lancer une analyse ────────────────────────────────────────────────────
@router.post("/analyze")
def analyze_url(
    data: UrlAnalyze,
    user_email: str = Depends(get_current_user)
):
    task = scan_url_task.delay(str(data.url), user_email)
    return {
        "task_id": task.id,
        "status":  "queued",
        "message": "Analyse démarrée"
    }


# ── Vérifier le statut d'une tâche ───────────────────────────────────────
@router.get("/analyze/status/{task_id}")
def get_task_status(task_id: str):
    result = AsyncResult(task_id, app=celery_app)

    if result.state == "PENDING":
        return {"task_id": task_id, "status": "pending", "message": "En attente..."}

    if result.state == "PROGRESS":
        info = result.info or {}
        return {
            "task_id":  task_id,
            "status":   "running",
            "message":  info.get("status", "En cours...") if isinstance(info, dict) else str(info),
            "progress": info.get("progress", 0) if isinstance(info, dict) else 0,
        }

    if result.state == "SUCCESS":
        return {"task_id": task_id, "status": "completed", "rapport": result.result}

    if result.state == "FAILURE":
        return {"task_id": task_id, "status": "failed", "error": str(result.result)}

    return {"task_id": task_id, "status": result.state, "message": ""}


# ── Récupérer un rapport par ID ───────────────────────────────────────────
@router.get("/analyze/report/{analysis_id}")
def get_report_by_id(
    analysis_id: int,
    user_email: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    entry = db.query(Analysis).filter(
        Analysis.id == analysis_id,
        Analysis.user_email == user_email
    ).first()

    if not entry:
        raise HTTPException(status_code=404, detail="Rapport non trouvé")

    # Désérialisation sécurisée — évite crash si full_report est corrompu
    try:
        full_report = json.loads(entry.full_report) if isinstance(entry.full_report, str) else entry.full_report
    except (json.JSONDecodeError, TypeError):
        full_report = {}

    return {
        "id":              str(entry.id),
        "url":             entry.url,
        "status":          entry.status,
        "date":            entry.created_at.strftime("%d %b %Y") if entry.created_at else "N/A",
        "time":            entry.created_at.strftime("%H:%M") if entry.created_at else None,
        "risk_score":      entry.risk_score,
        "recommendations": entry.recommendations,
        "full_report":     full_report,
    }


# ── Historique des analyses ───────────────────────────────────────────────
@router.get("/history")
def get_history(
    user_email: str = Depends(get_current_user),
    uc: AnalysisUseCases = Depends(get_use_case)
):
    return uc.get_history(user_email)


# ── Supprimer un item ────────────────────
@router.delete("/history/{item_id}")
def delete_history(
    item_id: int,
    db: Session = Depends(get_db),
    user_email: str = Depends(get_current_user)
):
    return delete_history_item(db, item_id, user_email)