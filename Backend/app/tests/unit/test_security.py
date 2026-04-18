from app.core.security import hash_password, verify_password, create_access_token, decode_access_token

def test_hash_password():
    hashed = hash_password("MonMotDePasse123!")
    assert hashed != "MonMotDePasse123!"  # pas en clair

def test_verify_password_correct():
    hashed = hash_password("MonMotDePasse123!")
    assert verify_password("MonMotDePasse123!", hashed) == True

def test_verify_password_wrong():
    hashed = hash_password("MonMotDePasse123!")
    assert verify_password("mauvais", hashed) == False

def test_token_creation_and_decode():
    token = create_access_token({"sub": "test@email.com"})
    payload = decode_access_token(token)
    assert payload["sub"] == "test@email.com"