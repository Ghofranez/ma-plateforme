from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.infrastructure.db.session import get_db
from app.infrastructure.repositories.analysis_repo import AnalysisRepository
from app.domain.use_cases.analysis_cases import AnalysisUseCases
from app.middleware.auth_middleware import get_current_user
from app.application.dto.analysis_dto import UrlAnalyze

router = APIRouter()

def get_use_case(db: Session = Depends(get_db)):
    return AnalysisUseCases(AnalysisRepository(db))

@router.post("/analyze")
def analyze_url(data: UrlAnalyze, user_email: str = Depends(get_current_user), uc: AnalysisUseCases = Depends(get_use_case)):
    return uc.analyze(data.url, user_email)

@router.get("/history")
def get_history(user_email: str = Depends(get_current_user), uc: AnalysisUseCases = Depends(get_use_case)):
    return uc.get_history(user_email)