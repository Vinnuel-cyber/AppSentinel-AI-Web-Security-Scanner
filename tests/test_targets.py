import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock
from app.models import db, User, Target, TargetAuditLog
from app.security.target_validator import TargetValidator


@pytest.fixture
def test_users(app):
    """Create two users for cross-user access control testing."""
    with app.app_context():
        user1 = User(username="analyst_alice", email="alice@targets.io", role="USER")
        user1.set_password("SecureAlice123!")
        user2 = User(username="analyst_bob", email="bob@targets.io", role="USER")
        user2.set_password("SecureBob1234!")
        admin = User(username="admin_carol", email="carol@targets.io", role="ADMIN")
        admin.set_password("AdminCarol123!")
        db.session.add_all([user1, user2, admin])
        db.session.commit()
        return user1.id, user2.id, admin.id


def test_add_target_success(client, test_users, monkeypatch):
    """Verify authenticated user can register a target with PENDING_VERIFICATION."""
    u1_id, _, _ = test_users
    # Login as Alice
    client.post("/auth/login", json={"login_id": "analyst_alice", "password": "SecureAlice123!"})

    # Mock DNS resolution to public IP
    monkeypatch.setattr(TargetValidator, "resolve_and_validate_hostname", lambda host, allow_private=False: ["93.184.216.34"])

    payload = {
        "name": "Alice Staging App",
        "target_url": "https://staging.alice-app.org:8443/home",
        "environment": "Staging",
        "description": "Staging cluster",
        "authorization_confirmed": True,
    }
    response = client.post("/targets/add", json=payload)
    assert response.status_code == 201
    data = response.get_json()
    assert data["status"] == "success"
    assert data["target"]["verification_status"] == "PENDING_VERIFICATION"
    assert data["target"]["is_verified"] is False
    assert data["target"]["domain"] == "staging.alice-app.org"


def test_add_target_duplicate_rejection(client, test_users, monkeypatch):
    """Verify duplicate target domain for the same user is rejected."""
    u1_id, _, _ = test_users
    client.post("/auth/login", json={"login_id": "analyst_alice", "password": "SecureAlice123!"})
    monkeypatch.setattr(TargetValidator, "resolve_and_validate_hostname", lambda host, allow_private=False: ["93.184.216.34"])

    payload = {
        "name": "First Instance",
        "target_url": "https://unique-domain.io",
        "authorization_confirmed": True,
    }
    r1 = client.post("/targets/add", json=payload)
    assert r1.status_code == 201

    # Attempt duplicate
    r2 = client.post("/targets/add", json=payload)
    assert r2.status_code == 400
    assert "Duplicate Target" in r2.get_json()["error"]


def test_add_target_unauthenticated_rejected(client):
    """Verify unauthenticated target creation is blocked."""
    response = client.post("/targets/add", json={"name": "Test", "target_url": "https://example.com"})
    assert response.status_code in (302, 401)


def test_add_target_ssrf_blocked_by_route(client, test_users):
    """Verify private/loopback URL is rejected with 400."""
    test_users
    client.post("/auth/login", json={"login_id": "analyst_alice", "password": "SecureAlice123!"})

    response = client.post("/targets/add", json={
        "name": "Internal Target",
        "target_url": "http://127.0.0.1:8080/admin",
        "authorization_confirmed": True,
    })
    assert response.status_code == 400
    data = response.get_json()
    assert "Security Validation Error" in data["error"]


def test_cross_user_target_access_forbidden(client, app, test_users):
    """Verify User Bob cannot view, edit, or delete User Alice's target (IDOR defense)."""
    u1_id, u2_id, _ = test_users
    with app.app_context():
        target = Target(
            owner_id=u1_id,
            name="Alice Private App",
            target_url="https://alice-private.io",
            domain="alice-private.io",
        )
        db.session.add(target)
        db.session.commit()
        t_id = target.id

    # Login as Bob
    client.post("/auth/login", json={"login_id": "analyst_bob", "password": "SecureBob1234!"})

    # Bob attempts to view Alice's target
    resp_get = client.get(f"/targets/{t_id}", json={})
    assert resp_get.status_code == 403

    # Bob attempts to edit Alice's target
    resp_edit = client.post(f"/targets/{t_id}/edit", json={"name": "Bob Hijack"})
    assert resp_edit.status_code == 403

    # Bob attempts to delete Alice's target
    resp_del = client.post(f"/targets/{t_id}/delete", json={})
    assert resp_del.status_code == 403


def test_target_soft_delete(client, app, test_users):
    """Verify target deletion sets is_active=False and soft-deletes record."""
    u1_id, _, _ = test_users
    with app.app_context():
        target = Target(
            owner_id=u1_id,
            name="To Be Deleted",
            target_url="https://delete-me.io",
            domain="delete-me.io",
        )
        db.session.add(target)
        db.session.commit()
        t_id = target.id

    client.post("/auth/login", json={"login_id": "analyst_alice", "password": "SecureAlice123!"})
    del_resp = client.post(f"/targets/{t_id}/delete", json={})
    assert del_resp.status_code == 200

    # Ensure soft-deleted target no longer returned in active queries
    with app.app_context():
        t = db.session.get(Target, t_id)
        assert t is not None
        assert t.is_active is False
        assert t.deleted_at is not None


def test_ownership_verification_http_success(client, app, test_users, monkeypatch):
    """Verify successful ownership verification via mock HTTP .well-known token."""
    u1_id, _, _ = test_users
    with app.app_context():
        target = Target(
            owner_id=u1_id,
            name="Verify Test Site",
            target_url="https://verify.example.org",
            domain="verify.example.org",
        )
        db.session.add(target)
        db.session.commit()
        t_id = target.id
        token = target.verification_token

    client.post("/auth/login", json={"login_id": "analyst_alice", "password": "SecureAlice123!"})

    # Mock HTTP verification success
    monkeypatch.setattr(
        TargetValidator,
        "verify_ownership_via_http",
        lambda domain, exp_token: (True, "Mock HTTP token confirmed.")
    )

    resp = client.post(f"/targets/{t_id}/verify", json={"method": "http_well_known"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "verified"

    with app.app_context():
        t = db.session.get(Target, t_id)
        assert t.is_verified is True
        assert t.verification_status == "VERIFIED"
        assert t.verification_method == "http_well_known"
        assert t.verified_at is not None


def test_ownership_verification_expired_token(client, app, test_users):
    """Verify expired token is rejected and automatically regenerated."""
    u1_id, _, _ = test_users
    with app.app_context():
        target = Target(
            owner_id=u1_id,
            name="Expired Site",
            target_url="https://expired.example.org",
            domain="expired.example.org",
            verification_expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        db.session.add(target)
        db.session.commit()
        t_id = target.id
        old_token = target.verification_token

    client.post("/auth/login", json={"login_id": "analyst_alice", "password": "SecureAlice123!"})
    resp = client.post(f"/targets/{t_id}/verify", json={"method": "http_well_known"})
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["status"] == "expired"
    assert data["new_token"] != old_token


def test_dashboard_target_metrics_integration(client, app, test_users):
    """Verify dashboard metrics count active targets and exclude deleted ones."""
    u1_id, _, _ = test_users
    with app.app_context():
        t_ver = Target(owner_id=u1_id, name="V", target_url="https://v.io", domain="v.io", is_verified=True, is_active=True)
        t_pend = Target(owner_id=u1_id, name="P", target_url="https://p.io", domain="p.io", is_verified=False, is_active=True)
        t_del = Target(owner_id=u1_id, name="D", target_url="https://d.io", domain="d.io", is_verified=True, is_active=False)
        db.session.add_all([t_ver, t_pend, t_del])
        db.session.commit()

    client.post("/auth/login", json={"login_id": "analyst_alice", "password": "SecureAlice123!"})
    resp = client.get("/dashboard", json={})
    assert resp.status_code == 200
    data = resp.get_json()
    metrics = data["metrics"]["targets"]

    # Deleted target must be excluded
    assert metrics["total"] == 2
    assert metrics["verified"] == 1
    assert metrics["pending"] == 1
