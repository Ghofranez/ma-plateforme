from app.infrastructure.db.session import Base, engine
from app.core.entities.user import User
from app.core.entities.analysis import Analysis

def init_db():
    Base.metadata.create_all(bind=engine)