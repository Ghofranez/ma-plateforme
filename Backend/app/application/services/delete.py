from sqlalchemy.orm import Session
from fastapi import HTTPException
from app.core.entities.analysis import Analysis


def delete_history_item(db: Session, item_id: int, user_email: str):
    # 1. Chercher l'item dans la base
    item = db.query(Analysis).filter(Analysis.id == item_id).first()

    # 2. Vérifier qu'il existe
    if not item:
        raise HTTPException(status_code=404, detail="Item introuvable")

    # 3. Vérifier que l'item appartient à l'utilisateur connecté
    if item.user_email != user_email:
        raise HTTPException(status_code=403, detail="Accès refusé")

    # 4. Supprimer et sauvegarder
    db.delete(item)
    db.commit()
    return {"message": "Supprimé avec succès"}