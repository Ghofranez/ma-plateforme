from sqlalchemy.orm import Session
from fastapi import HTTPException
from app.core.entities.analysis import Analysis

def delete_history_item(db: Session, item_id: int, user_email: str, user_id: int = None):
    item = db.query(Analysis).filter(Analysis.id == item_id).first()

    if not item:
        raise HTTPException(status_code=404, detail="Item introuvable")

    # Vérifie par user_id OU par user_email (les scans auto peuvent avoir un email différent)
    owned_by_email = item.user_email == user_email
    owned_by_id    = user_id is not None and item.user_id == user_id

    if not owned_by_email and not owned_by_id:
        raise HTTPException(status_code=403, detail="Accès refusé")

    db.delete(item)
    db.commit()
    return {"message": "Supprimé avec succès"}