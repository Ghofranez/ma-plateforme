import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.infrastructure.db.session import engine, Base
from app.core.entities.user import User
from app.core.entities.analysis import Analysis
from app.interface.routes import auth, profile, analysis
from app.infrastructure.db.init_db import init_db

# Création des tables
Base.metadata.create_all(bind=engine)

# Initialisation FastAPI
app = FastAPI(title="Plateforme Analyse Sécurité")

# Configuration CORS (autoriser frontend)
origins = [
    "http://localhost:5173",    # Vite dev
    "http://127.0.0.1:5173",
    "http://localhost:3000",    # Docker frontend
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Inclusion des routes
app.include_router(auth.router,     tags=["Auth"])
app.include_router(profile.router,  tags=["Profile"])
app.include_router(analysis.router, tags=["Analysis"])

# Initialisation DB au démarrage
@app.on_event("startup")
def startup():
    init_db()

# Endpoint santé
@app.get("/")
def health():
    return {"status": "ok"}
