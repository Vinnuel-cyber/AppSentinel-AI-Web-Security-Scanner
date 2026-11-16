from app import create_app
from app.models import db, User
from app.security.access_control import login_rate_limiter


def test_session_cookie_security_config():
    """Verify session cookie security settings meet standards."""
    app = create_app("production")
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] in ("Lax", "Strict")
    assert app.config["SESSION_COOKIE_SECURE"] is True
    assert app.config["REMEMBER_COOKIE_HTTPONLY"] is True
    assert app.config["REMEMBER_COOKIE_SECURE"] is True


def test_csrf_protection_rejection():
    """Verify state-changing POST without CSRF token is rejected when CSRF enabled."""
    app = create_app("development")
    app.config["WTF_CSRF_ENABLED"] = True

    with app.test_client() as client:
        # Attempt POST without CSRF token
        response = client.post(
            "/auth/login",
            data={"login_id": "anyuser", "password": "Password123!"},
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "CSRF" in data.get("error", "") or "CSRF" in data.get("message", "")


def test_login_rate_limiter_brute_force_prevention(client, app):
    """Verify repeated failed logins trigger 429 Rate Limited."""
    with app.app_context():
        u = User(username="brute_target", email="target@appsentinel.io")
        u.set_password("CorrectPassword123!")
        db.session.add(u)
        db.session.commit()

    # Reset any existing counts
    login_rate_limiter.reset("127.0.0.1:brute_target")

    # Fail 5 times
    for _ in range(5):
        resp = client.post("/auth/login", json={"login_id": "brute_target", "password": "WrongPassword"})
        assert resp.status_code == 401

    # 6th attempt should be blocked with 429 Rate Limited
    blocked_resp = client.post("/auth/login", json={"login_id": "brute_target", "password": "WrongPassword"})
    assert blocked_resp.status_code == 429
    data = blocked_resp.get_json()
    assert "Rate Limited" in data.get("error", "")

    # Cleanup
    login_rate_limiter.reset("127.0.0.1:brute_target")
