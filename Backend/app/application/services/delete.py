from sqlalchemy.orm import Session
from fastapi import HTTPException
from app.core.entities.analysis import Analysis


def delete_history_item(db: Session, item_id: int, user_id: int):
    item = db.query(Analysis).filter(Analysis.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item introuvable")

    if item.user_id != user_id:
        raise HTTPException(status_code=403, detail="Accès refusé")

    db.delete(item)
    db.commit()
    return {"message": "Supprimé avec succès"}