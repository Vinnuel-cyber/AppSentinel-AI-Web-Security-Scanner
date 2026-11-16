import pytest
from app.models import (
    db,
    User,
    Target,
    Scan,
    Vulnerability,
    OWASPAssessment,
    RiskAssessment,
)


@pytest.fixture
def owasp_test_users(app):
    """Fixture providing Alice (Target Owner), Bob (Other User), and Carol (Admin)."""
    with app.app_context():
        alice = User(username="alice_owasp", email="alice@owasp.test", role="USER")
        alice.set_password("AliceSecure123!")
        bob = User(username="bob_owasp", email="bob@owasp.test", role="USER")
        bob.set_password("BobSecure1234!")
        admin = User(username="admin_owasp", email="admin@owasp.test", role="ADMIN")
        admin.set_password("AdminSecure123!")
        db.session.add_all([alice, bob, admin])
        db.session.commit()
        return alice.id, bob.id, admin.id


@pytest.fixture
def target_with_findings(client, owasp_test_users):
    """Fixture providing a verified target owned by Alice with sample vulnerabilities."""
    alice_id, _, _ = owasp_test_users
    with client.application.app_context():
        target = Target(
            name="Alice Enterprise App",
            target_url="https://app.alice-enterprise.test",
            domain="app.alice-enterprise.test",
            owner_id=alice_id,
            is_verified=True,
            verification_status="VERIFIED",
            verification_method="dns_txt",
            environment="Production",
        )
        db.session.add(target)
        db.session.commit()

        scan = Scan(target_id=target.id, user_id=alice_id, status="completed")
        db.session.add(scan)
        db.session.commit()

        v1 = Vulnerability(
            scan_id=scan.id,
            target_id=target.id,
            title="SQL Injection (SQLite Error-Based)",
            vulnerability_type="Injection",
            owasp_category="A03:2021 - Injection",
            severity="CRITICAL",
            confidence="CONFIRMED",
            scanner_module="sqli_scanner",
            affected_url="https://app.alice-enterprise.test/search?q=test",
            parameter="q",
            description="SQL injection in search",
            cwe_id="CWE-89",
        )
        v2 = Vulnerability(
            scan_id=scan.id,
            target_id=target.id,
            title="Missing Defensive Header: Content-Security-Policy",
            vulnerability_type="Security Misconfiguration",
            owasp_category="A05:2021 - Security Misconfiguration",
            severity="HIGH",
            confidence="HIGH",
            scanner_module="misconfiguration_scanner",
            affected_url="https://app.alice-enterprise.test/",
            description="CSP missing",
            cwe_id="CWE-693",
        )
        db.session.add_all([v1, v2])
        db.session.commit()
        return target.id, v1.id, v2.id


def test_owasp_unauthenticated_redirect(client):
    """Verify unauthenticated access to OWASP and Risk dashboards redirects to login."""
    resp1 = client.get("/owasp", follow_redirects=False)
    assert resp1.status_code in (302, 401)

    resp2 = client.get("/risk", follow_redirects=False)
    assert resp2.status_code in (302, 401)


def test_owasp_analyze_target_success(client, owasp_test_users, target_with_findings):
    """Verify Alice can execute OWASP analysis and generate assessments and risk records."""
    target_id, v1_id, v2_id = target_with_findings
    client.post("/auth/login", json={"login_id": "alice_owasp", "password": "AliceSecure123!"})

    resp = client.post(f"/owasp/analyze/{target_id}", json={})
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["total_findings_mapped"] == 2
    assert "A03:2021" in data["summary"]["category_distribution"]

    # Verify risk view for target
    risk_resp = client.get(f"/risk/target/{target_id}")
    assert risk_resp.status_code == 200
    assert b"SQL Injection" in risk_resp.data
    assert b"CVSS v4.0" in risk_resp.data


def test_owasp_cross_user_isolation(client, owasp_test_users, target_with_findings):
    """Verify Bob cannot access or analyze Alice's target (IDOR defense)."""
    target_id, _, _ = target_with_findings
    client.post("/auth/login", json={"login_id": "bob_owasp", "password": "BobSecure1234!"})

    # Bob attempts to analyze Alice's target -> 403 Forbidden
    resp = client.post(f"/owasp/analyze/{target_id}", json={})
    assert resp.status_code == 403

    # Bob attempts to view Alice's OWASP assessment -> 403 Forbidden
    resp_view = client.get(f"/owasp/assessment/{target_id}")
    assert resp_view.status_code == 403

    # Bob attempts to view Alice's risk profile -> 403 Forbidden
    resp_risk = client.get(f"/risk/target/{target_id}")
    assert resp_risk.status_code == 403


def test_admin_can_access_all_targets_owasp(client, owasp_test_users, target_with_findings):
    """Verify Admin can view and analyze any verified target across users."""
    target_id, _, _ = target_with_findings
    client.post("/auth/login", json={"login_id": "admin_owasp", "password": "AdminSecure123!"})

    resp = client.post(f"/owasp/analyze/{target_id}", json={})
    assert resp.status_code == 201

    view_resp = client.get(f"/owasp/assessment/{target_id}")
    assert view_resp.status_code == 200
    assert b"Alice Enterprise App" in view_resp.data


def test_finding_risk_details_route(client, owasp_test_users, target_with_findings):
    """Verify finding risk endpoint renders CVSS v4.0 vector string and scoring factors."""
    target_id, v1_id, _ = target_with_findings
    client.post("/auth/login", json={"login_id": "alice_owasp", "password": "AliceSecure123!"})

    # First analyze
    client.post(f"/owasp/analyze/{target_id}", json={})

    # View finding risk detail
    detail_resp = client.get(f"/risk/finding/{v1_id}")
    assert detail_resp.status_code == 200
    assert b"CVSS:4.0/" in detail_resp.data
    assert b"P1" in detail_resp.data
    assert b"Remediation" in detail_resp.data
