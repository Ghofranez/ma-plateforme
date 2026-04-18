from app.application.services.otp import (
    generate_code, store_login_code,
    verify_login_code, store_reset_code,
    verify_reset_code, clear_reset_code
)

def test_generate_code():
    code = generate_code()
    assert len(code) == 6
    assert code.isdigit()

def test_login_code_valid():
    store_login_code("user@test.com")
    from app.application.services.otp import email_verification
    code = email_verification["user@test.com"]["code"]
    assert verify_login_code("user@test.com", code) == True

def test_login_code_wrong():
    store_login_code("user2@test.com")
    assert verify_login_code("user2@test.com", "000000") == False

def test_reset_code_flow():
    store_reset_code("reset@test.com")
    from app.application.services.otp import reset_verification
    code = reset_verification["reset@test.com"]["code"]
    assert verify_reset_code("reset@test.com", code) == True
    clear_reset_code("reset@test.com")
    assert verify_reset_code("reset@test.com", code) == False