from fastapi          import APIRouter, Depends, HTTPException
from sqlalchemy.orm   import Session
from pydantic         import BaseModel

from app.infrastructure.db.session                     import get_db
from app.infrastructure.repositories.surveillance_repo import SurveillanceRepository
from app.middleware.auth_middleware                     import get_current_user
from app.core.entities.user                            import User

router = APIRouter(prefix="/surveillance", tags=["surveillance"])

class SurveillanceRequest(BaseModel):
    url: str


@router.post("/activer")
def activer(
    req:          SurveillanceRequest,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    repo      = SurveillanceRepository(db)
    existante = repo.get_status(current_user.id, req.url)
    if existante:
        return {"status": "active", "url": req.url,
                "next_scan_at": existante.next_scan_at, "already_active": True}

    s = repo.activer(current_user.id, current_user.email, req.url)
    return {"status": "active", "url": req.url, "next_scan_at": s.next_scan_at}


@router.post("/desactiver")
def desactiver(
    req:          SurveillanceRequest,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    repo      = SurveillanceRepository(db)
    existante = repo.get_status(current_user.id, req.url)
    if not existante:
        raise HTTPException(status_code=404, detail={"error": "Aucune surveillance active pour cette URL."})

    repo.desactiver(current_user.id, req.url)
    return {"status": "inactive", "url": req.url, "message": "Surveillance désactivée."}


@router.get("/status")
def status(
    url:          str,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    s = SurveillanceRepository(db).get_status(current_user.id, url)
    if not s:
        return {"active": False, "url": url}
    return {"active": True, "url": url,
            "next_scan_at": s.next_scan_at, "last_scan_at": s.last_scan_at}


@router.get("/mes-surveillances")
def mes_surveillances(
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    repo    = SurveillanceRepository(db)
    actives = repo.get_all_active_by_user(current_user.id)
    return {
        "total": len(actives),
        "urls": [{"url": s.url, "next_scan_at": s.next_scan_at,
                  "last_scan_at": s.last_scan_at} for s in actives],
    }