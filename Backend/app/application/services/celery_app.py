from celery import Celery
from app.core.config import settings

# ── Créer l'instance Celery ────────────────────────────
celery_app = Celery(
    "ma_plateforme",                              # nom de l'app
    broker=settings.REDIS_URL,                    # Redis reçoit les tâches
    backend=settings.REDIS_URL,                   # Redis stocke les résultats
    include=["app.application.services.tasks"]    # fichier des tâches
)

celery_app.conf.update(
    task_serializer="json",       # format des tâches
    result_serializer="json",     # format des résultats
    accept_content=["json"],
    result_expires=3600,          # résultats gardés 1h en Redis
    task_track_started=True,      # voir quand une tâche démarre
    worker_prefetch_multiplier=1, # un worker prend une tâche à la fois
)