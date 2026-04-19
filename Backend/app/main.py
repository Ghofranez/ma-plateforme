from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.infrastructure.db.session import engine, Base
from app.core.entities.user import User
from app.core.entities.analysis import Analysis
from app.interface.routes import auth, profile, analysis

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Plateforme Analyse Sécurité")

@app.get("/")
def health():
    return {"status": "ok"}

origins = [
    "http://localhost:5173",    # Vite dev
    "http://127.0.0.1:5173",
    "http://localhost:3000",    # Docker frontend
    "http://127.0.0.1:3000",
    "http://localhost:80",
    "http://127.0.0.1:80",
     "http://localhost",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router,     tags=["Auth"])
app.include_router(profile.router,  tags=["Profile"])
app.include_router(analysis.router, tags=["Analysis"])