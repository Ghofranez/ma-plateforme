from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.infrastructure.db.init_db import init_db
from app.interface.routes import auth, profile, analysis
from app.interface.routes.surveillance import router as surveillance_router
from app.interface.routes.tasks_router import router as tasks_router  

app = FastAPI(title="Plateforme Analyse Sécurité")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router,        tags=["Auth"])
app.include_router(profile.router,     tags=["Profile"])
app.include_router(analysis.router,    tags=["Analysis"])
app.include_router(surveillance_router)
app.include_router(tasks_router)

@app.on_event("startup")
def startup():
    init_db()

@app.get("/")
def health():
    return {"status": "ok"}