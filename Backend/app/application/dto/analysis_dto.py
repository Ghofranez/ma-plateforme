# ── Modèle de validation pour la requête d'analyse ──────────────
# Pydantic rejette automatiquement les URLs mal formées

from pydantic import BaseModel, HttpUrl
from typing import Optional


class UrlAnalyze(BaseModel):
    url: HttpUrl                            # URL à analyser — validée automatiquement
    scan_depth: Optional[int] = 1           # profondeur (1=basique, 2=approfondi)
    include_headers: Optional[bool] = True  # activer SecurityHeaders
    include_ssl: Optional[bool] = True      # activer SSL Labs