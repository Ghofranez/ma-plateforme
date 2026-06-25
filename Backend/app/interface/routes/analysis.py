import json
import os
import redis

from fastapi         import APIRouter, Depends, HTTPException
from sqlalchemy.orm  import Session
from celery.result   import AsyncResult
from datetime        import datetime

from app.infrastructure.db.session                 import get_db
from app.infrastructure.repositories.analysis_repo import AnalysisRepository
from app.domain.use_cases.analysis_cases           import AnalysisUseCases
from app.middleware.auth_middleware                 import get_current_user
from app.application.dto.analysis_dto              import UrlAnalyze
from app.application.services.tasks                import scan_url_task
from app.application.services.celery_app           import celery_app
from app.core.entities.analysis                    import Analysis
from app.core.entities.user                        import User
from app.application.services.delete               import delete_history_item

router = APIRouter()

def get_redis():
    return redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"))

def get_use_case(db: Session = Depends(get_db)):
    return AnalysisUseCases(AnalysisRepository(db))


@router.post("/analyze")
def analyze_url(
    data:         UrlAnalyze,
    current_user: User    = Depends(get_current_user),
    db:           Session = Depends(get_db),
):

    task = scan_url_task.delay(str(data.url), current_user.id, data.surveillance_id)

    db_analysis = Analysis(
        user_id    = current_user.id,
        url        = str(data.url),
        status     = "processing",
        reference  = task.id,
        surveillance_id=data.surveillance_id,
    )
    db.add(db_analysis)
    db.commit()
    db.refresh(db_analysis)

    r = get_redis()
    r.setex(
        f"scan:{current_user.id}:{task.id}",
        7200,
        json.dumps({"url": str(data.url), "task_id": task.id})
    )

    return {"task_id": task.id, "status": "queued", "message": "Analyse démarrée"}


@router.get("/analyze/status/{task_id}")
def get_task_status(task_id: str):
    result = AsyncResult(task_id, app=celery_app)

    if result.state == "PENDING":
        return {"task_id": task_id, "state": "PENDING", "status": "pending",
                "meta": {"progress": 0, "current_tool": None, "current_label": None,
                         "status": "En attente de démarrage…", "partial_results": {}}}

    if result.state == "PROGRESS":
        info = result.info if isinstance(result.info, dict) else {}
        return {"task_id": task_id, "state": "PROGRESS", "status": "running",
                "meta": {"progress": info.get("progress", 0),
                         "current_tool": info.get("current_tool", None),
                         "current_label": info.get("current_label", None),
                         "status": info.get("status", "Analyse en cours…"),
                         "partial_results": info.get("partial_results", {})}}

    if result.state == "SUCCESS":
        res = result.result or {}
        if isinstance(res, dict) and res.get("from_cache"):
            return {"task_id": task_id, "state": "SUCCESS", "status": "from_cache",
                    "report_id": res.get("report_id"),
                    "minutes_restantes": res.get("minutes_restantes", 60),
                    "meta": {"progress": 100, "current_tool": None, "current_label": None,
                             "status": "Rapport existant trouvé", "partial_results": {}}}
        return {"task_id": task_id, "state": "SUCCESS", "status": "completed",
                "rapport": res,
                "meta": {"progress": 100, "current_tool": None, "current_label": None,
                         "status": "Analyse terminée",
                         "partial_results": res.get("display", {}).get("sections", {})}}

    if result.state == "FAILURE":
        return {"task_id": task_id, "state": "FAILURE", "status": "failed",
                "error": str(result.result),
                "meta": {"progress": 0, "current_tool": None, "current_label": None,
                         "status": "Échec de l'analyse", "partial_results": {}}}

    return {"task_id": task_id, "state": result.state, "status": "pending",
            "meta": {"progress": 0, "current_tool": None, "current_label": None,
                     "status": f"État : {result.state}", "partial_results": {}}}


@router.get("/analyze/report/{analysis_id}")
def get_report_by_id(
    analysis_id:  int,
    current_user: User    = Depends(get_current_user),
    db:           Session = Depends(get_db),
):
    entry = db.query(Analysis).filter(
        Analysis.id      == analysis_id,
        Analysis.user_id == current_user.id,
    ).first()

    if not entry:
        raise HTTPException(status_code=404, detail="Rapport non trouvé")

    return {
        "id":              str(entry.id),
        "url":             entry.url,
        "status":          entry.status,
        "date":            entry.created_at.strftime("%d %b %Y") if entry.created_at else "N/A",
        "time":            entry.created_at.strftime("%H:%M")    if entry.created_at else None,
        "risk_score":      entry.risk_score,
        "recommendations": entry.recommendations,
        "full_report":     entry.full_report,
    }


@router.get("/history")
def get_history(
    current_user: User           = Depends(get_current_user),
    uc:           AnalysisUseCases = Depends(get_use_case),
):
    return uc.get_history(current_user.id)


@router.delete("/history/{item_id}")
def delete_history(
    item_id:      int,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    return delete_history_item(db, item_id, user_id=current_user.id)


@router.get("/tasks/en-cours")
def get_tasks_en_cours(
    current_user: User    = Depends(get_current_user),
    db:           Session = Depends(get_db),
):
    r    = get_redis()
    keys = r.keys(f"scan:{current_user.id}:*")
    tasks = []

    for key in keys:
        data = r.get(key)
        if not data:
            continue
        info    = json.loads(data)
        task_id = info["task_id"]
        url     = info["url"]
        result  = AsyncResult(task_id, app=celery_app)

        if result.state in ("SUCCESS", "FAILURE", "REVOKED"):
            r.delete(key)
            continue

        task_info     = result.info if isinstance(result.info, dict) else {}
        mapped_status = "running" if result.state in ("PROGRESS", "STARTED") else "pending"

        tasks.append({
            "taskId":          task_id,
            "url":             url,
            "status":          mapped_status,
            "progress":        task_info.get("progress", 5 if mapped_status == "pending" else 10),
            "current_tool":    task_info.get("current_tool",  None),
            "current_label":   task_info.get("current_label", None),
            "message":         task_info.get("status",        "Analyse en cours…"),
            "partial_results": task_info.get("partial_results", {}),
        })

    return {"tasks": tasks}


