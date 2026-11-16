import pytest
from app.models import db, User


def test_successful_user_registration(client, app):
    """Verify standard user registration with strong password."""
    payload = {
        "full_name": "Bob Analyst",
        "username": "bob_analyst",
        "email": "bob@appsentinel.io",
        "password": "SecurePassword123!",
        "confirm_password": "SecurePassword123!",
    }
    response = client.post("/auth/register", json=payload)
    assert response.status_code == 201
    data = response.get_json()
    assert data["status"] == "success"
    assert data["user"]["username"] == "bob_analyst"
    assert data["user"]["role"] == "USER"

    with app.app_context():
        user = User.query.filter_by(username="bob_analyst").first()
        assert user is not None
        assert user.check_password("SecurePassword123!") is True
        assert user.role == "USER"


def test_registration_duplicate_username(client, app):
    """Verify duplicate username registration is rejected."""
    with app.app_context():
        u = User(username="existing_user", email="existing@appsentinel.io")
        u.set_password("ValidPass123!")
        db.session.add(u)
        db.session.commit()

    payload = {
        "full_name": "Duplicate Tester",
        "username": "existing_user",
        "email": "different@appsentinel.io",
        "password": "ValidPass123!",
        "confirm_password": "ValidPass123!",
    }
    response = client.post("/auth/register", json=payload)
    assert response.status_code == 400
    data = response.get_json()
    assert "username" in data.get("errors", {})


def test_registration_duplicate_email(client, app):
    """Verify duplicate email registration is rejected."""
    with app.app_context():
        u = User(username="user_one", email="shared@appsentinel.io")
        u.set_password("ValidPass123!")
        db.session.add(u)
        db.session.commit()

    payload = {
        "full_name": "Second User",
        "username": "user_two",
        "email": "shared@appsentinel.io",
        "password": "ValidPass123!",
        "confirm_password": "ValidPass123!",
    }
    response = client.post("/auth/register", json=payload)
    assert response.status_code == 400
    data = response.get_json()
    assert "email" in data.get("errors", {})


def test_registration_invalid_email(client):
    """Verify malformed email address is rejected."""
    payload = {
        "full_name": "Invalid Email",
        "username": "invalid_email_user",
        "email": "not-a-valid-email",
        "password": "ValidPass123!",
        "confirm_password": "ValidPass123!",
    }
    response = client.post("/auth/register", json=payload)
    assert response.status_code == 400
    data = response.get_json()
    assert "email" in data.get("errors", {})


def test_registration_weak_password(client):
    """Verify password failing complexity checks is rejected."""
    payload = {
        "full_name": "Weak Pass User",
        "username": "weak_pass_user",
        "email": "weak@appsentinel.io",
        "password": "weak",
        "confirm_password": "weak",
    }
    response = client.post("/auth/register", json=payload)
    assert response.status_code == 400
    data = response.get_json()
    assert "password" in data.get("errors", {})


def test_registration_password_mismatch(client):
    """Verify non-matching confirm password is rejected."""
    payload = {
        "full_name": "Mismatch User",
        "username": "mismatch_user",
        "email": "mismatch@appsentinel.io",
        "password": "ValidPassword123!",
        "confirm_password": "DifferentPassword123!",
    }
    response = client.post("/auth/register", json=payload)
    assert response.status_code == 400
    data = response.get_json()
    assert "confirm_password" in data.get("errors", {})


def test_registration_role_escalation_prevented(client, app):
    """Verify registration ignores arbitrary role parameter and forces USER."""
    payload = {
        "full_name": "Escalation Attacker",
        "username": "attacker",
        "email": "attacker@appsentinel.io",
        "password": "AttackerPass123!",
        "confirm_password": "AttackerPass123!",
        "role": "ADMIN",  # Attempted escalation
    }
    response = client.post("/auth/register", json=payload)
    assert response.status_code == 201

    with app.app_context():
        user = User.query.filter_by(username="attacker").first()
        assert user.role == "USER"
        assert user.is_admin() is False


def test_successful_login_with_username(client, app):
    """Verify user can authenticate using username."""
    with app.app_context():
        u = User(username="analyst_login", email="login1@appsentinel.io", role="USER")
        u.set_password("LoginPass123!")
        db.session.add(u)
        db.session.commit()

    payload = {"login_id": "analyst_login", "password": "LoginPass123!"}
    response = client.post("/auth/login", json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert data["user"]["username"] == "analyst_login"


def test_successful_login_with_email(client, app):
    """Verify user can authenticate using email address."""
    with app.app_context():
        u = User(username="email_analyst", email="email_auth@appsentinel.io", role="USER")
        u.set_password("LoginPass123!")
        db.session.add(u)
        db.session.commit()

    payload = {"login_id": "email_auth@appsentinel.io", "password": "LoginPass123!"}
    response = client.post("/auth/login", json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"


def test_login_incorrect_password(client, app):
    """Verify incorrect password returns generic 401 error."""
    with app.app_context():
        u = User(username="valid_user", email="valid@appsentinel.io")
        u.set_password("ValidPassword123!")
        db.session.add(u)
        db.session.commit()

    payload = {"login_id": "valid_user", "password": "WrongPassword123!"}
    response = client.post("/auth/login", json=payload)
    assert response.status_code == 401
    data = response.get_json()
    assert data["message"] == "Invalid username/email or password."


def test_login_unknown_user(client):
    """Verify nonexistent user returns generic 401 error without user enumeration."""
    payload = {"login_id": "nonexistent_operator", "password": "SomePassword123!"}
    response = client.post("/auth/login", json=payload)
    assert response.status_code == 401
    data = response.get_json()
    assert data["message"] == "Invalid username/email or password."


def test_login_disabled_account(client, app):
    """Verify inactive account is blocked from signing in."""
    with app.app_context():
        u = User(username="disabled_user", email="disabled@appsentinel.io", is_active=False)
        u.set_password("ValidPassword123!")
        db.session.add(u)
        db.session.commit()

    payload = {"login_id": "disabled_user", "password": "ValidPassword123!"}
    response = client.post("/auth/login", json=payload)
    assert response.status_code == 403
    data = response.get_json()
    assert "disabled" in data["message"].lower()


def test_successful_logout(client, app):
    """Verify user session is cleared upon logout."""
    with app.app_context():
        u = User(username="logout_user", email="logout@appsentinel.io")
        u.set_password("LogoutPassword123!")
        db.session.add(u)
        db.session.commit()

    # Login
    client.post("/auth/login", json={"login_id": "logout_user", "password": "LogoutPassword123!"})

    # Verify profile accessible
    prof = client.get("/profile", json={})
    assert prof.status_code == 200

    # Logout
    logout_resp = client.post("/auth/logout", json={})
    assert logout_resp.status_code == 200

    # Profile now requires authentication
    prof_after = client.get("/profile")
    assert prof_after.status_code in (302, 401)
