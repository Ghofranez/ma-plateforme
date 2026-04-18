from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from main import app
from app.infrastructure.db.session import Base, get_db

# ─────────────────────────────
# DB de test séparée (SQLite en mémoire)
# ─────────────────────────────
TEST_DATABASE_URL = "sqlite:///./test.db"

engine_test = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(bind=engine_test)

# Remplace la DB réelle par la DB de test
def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)

# ─────────────────────────────
# Setup / Teardown — recrée la DB avant chaque test
# ─────────────────────────────
import pytest

@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.create_all(bind=engine_test)   # crée les tables
    yield
    Base.metadata.drop_all(bind=engine_test)     # efface tout après

# ─────────────────────────────
# TESTS
# ─────────────────────────────
def test_register():
    response = client.post("/register", json={
        "nom": "Test",
        "prenom": "User",
        "cin": "12345678",
        "email": "testuser@test.com",
        "password": "Password123!",
        "confirm_password": "Password123!"
    })
    assert response.status_code == 200
    assert response.json()["message"] == "User created"

def test_register_duplicate_email():
    # Premier register
    client.post("/register", json={
        "nom": "Test",
        "prenom": "User",
        "cin": "12345678",
        "email": "testuser@test.com",
        "password": "Password123!",
        "confirm_password": "Password123!"
    })
    # Deuxième register même email → doit échouer
    response = client.post("/register", json={
        "nom": "Test2",
        "prenom": "User2",
        "cin": "87654321",
        "email": "testuser@test.com",
        "password": "Password123!",
        "confirm_password": "Password123!"
    })
    assert response.status_code == 400
    assert response.json()["detail"] == "Email already used"

def test_login_wrong_password():
    response = client.post("/login", json={
        "email": "testuser@test.com",
        "password": "mauvais"
    })
    assert response.status_code == 401

def test_protected_route_without_token():
    response = client.get("/me")
    assert response.status_code == 401