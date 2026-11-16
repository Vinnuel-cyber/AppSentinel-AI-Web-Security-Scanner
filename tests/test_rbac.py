from app.models import db, User, Target


def test_admin_access_to_admin_users(client, app):
    """Verify ADMIN user can access administrative endpoints."""
    with app.app_context():
        admin = User(username="sec_admin", email="admin@appsentinel.io", role="ADMIN")
        admin.set_password("AdminSecure2026!")
        db.session.add(admin)
        db.session.commit()

    # Login as admin
    client.post("/auth/login", json={"login_id": "sec_admin", "password": "AdminSecure2026!"})

    resp = client.get("/admin/users", json={})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "users" in data
    assert data["total_users"] >= 1


def test_user_forbidden_from_admin_users(client, app):
    """Verify standard USER receives 403 Forbidden on administrative endpoints."""
    with app.app_context():
        user = User(username="standard_user", email="user@appsentinel.io", role="USER")
        user.set_password("UserPassword2026!")
        db.session.add(user)
        db.session.commit()

    # Login as normal user
    client.post("/auth/login", json={"login_id": "standard_user", "password": "UserPassword2026!"})

    resp = client.get("/admin/users", json={})
    assert resp.status_code == 403
    data = resp.get_json()
    assert data["error"] == "Forbidden"


def test_unauthenticated_access_denied(client):
    """Verify unauthenticated requests to protected endpoints are redirected or rejected."""
    resp = client.get("/admin/users")
    assert resp.status_code in (302, 401)

    prof = client.get("/profile")
    assert prof.status_code in (302, 401)


def test_create_admin_cli_command(runner, app):
    """Verify flask create-admin CLI bootstrap command."""
    result = runner.invoke(
        args=[
            "create-admin",
            "--username", "bootstrap_admin",
            "--email", "bootstrap@appsentinel.io",
            "--password", "StrongAdminPass123!",
            "--full-name", "Bootstrap Admin",
        ]
    )
    assert result.exit_code == 0
    assert "created successfully" in result.output

    with app.app_context():
        admin = User.query.filter_by(username="bootstrap_admin").first()
        assert admin is not None
        assert admin.is_admin() is True
        assert admin.check_password("StrongAdminPass123!") is True


def test_cross_user_target_isolation(app):
    """Verify target ownership relationships prevent cross-user data exposure."""
    with app.app_context():
        user_a = User(username="user_a", email="a@appsentinel.io", role="USER")
        user_a.set_password("PasswordA123!")
        user_b = User(username="user_b", email="b@appsentinel.io", role="USER")
        user_b.set_password("PasswordB123!")
        db.session.add_all([user_a, user_b])
        db.session.commit()

        target_a = Target(name="Target A", target_url="https://site-a.example.com", owner_id=user_a.id)
        target_b = Target(name="Target B", target_url="https://site-b.example.com", owner_id=user_b.id)
        db.session.add_all([target_a, target_b])
        db.session.commit()

        # User A's targets must not include User B's targets
        assert user_a.targets.count() == 1
        assert user_a.targets.first().domain == "site-a.example.com"
        assert user_b.targets.count() == 1
        assert user_b.targets.first().domain == "site-b.example.com"
