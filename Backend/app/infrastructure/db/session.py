from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from app.core.config import settings

if not settings.DATABASE_URL:
    raise ValueError("DATABASE_URL manquante dans .env !")
Base = declarative_base()
engine = create_engine(settings.DATABASE_URL,pool_pre_ping=True, pool_recycle=3600)
SessionLocal = sessionmaker(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()