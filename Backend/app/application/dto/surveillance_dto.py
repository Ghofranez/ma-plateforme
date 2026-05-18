"""
app/application/dto/surveillance.py
"""
from pydantic import BaseModel, HttpUrl
from typing import Optional
from datetime import datetime


# ─── Requêtes ────────────────────────────────────────────────────────────────

class SurveillanceActiverRequest(BaseModel):
    url: HttpUrl


class SurveillanceDesactiverRequest(BaseModel):
    url: HttpUrl


# ─── Réponses ────────────────────────────────────────────────────────────────

class SurveillanceStatusResponse(BaseModel):
    url:          str
    active:       bool
    last_scan_at: Optional[datetime] = None
    next_scan_at: Optional[datetime] = None
    created_at:   Optional[datetime] = None

    class Config:
        from_attributes = True


class SurveillanceListResponse(BaseModel):
    surveillances: list[SurveillanceStatusResponse]