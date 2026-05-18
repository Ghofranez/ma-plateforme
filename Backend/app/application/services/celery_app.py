"""
celery_app.py — Configuration Celery + Beat schedule
"""
from celery import Celery
from celery.schedules import crontab
from app.core.config import settings

celery_app = Celery(
    "ma_plateforme",
    broker  = settings.REDIS_URL,
    backend = settings.REDIS_URL,
    include = [
        "app.application.services.tasks",
        "app.application.services.surveillance_task",
    ]
)

celery_app.conf.update(
    broker_connection_retry_on_startup = True,
    task_serializer           = "json",
    result_serializer         = "json",
    accept_content            = ["json"],
    result_expires            = 3600,
    task_track_started        = True,
    worker_prefetch_multiplier = 1,
    task_soft_time_limit      = 1800,
    task_time_limit           = 2000,
    beat_timezone             = "Africa/Tunis",


    # ── Planning surveillance automatique ──────────────
 beat_schedule = {
    # Scan complet — timer individuel 24h par URL
    "scan-surveillance-24h": {
        "task":     "app.application.services.surveillance_task.scan_complet_toutes_urls",
        "schedule": crontab(minute=0),
    },
    # Uptime — toutes les 5 minutes
    "scan-uptime": {
        "task":     "app.application.services.surveillance_task.scan_uptime_toutes_urls",
        "schedule": crontab(minute="*/5"),
    },

},
)