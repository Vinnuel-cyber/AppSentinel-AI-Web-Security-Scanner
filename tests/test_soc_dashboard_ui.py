"""AppSentinel - Enterprise SOC Dashboard UI & Navigation Verification Tests.

Validates the redesigned SOC interface:
1. Collapsible sidebar navigation & active links.
2. Topbar with breadcrumbs, system health indicator, and user controls.
3. Four primary KPI metric cards with real database values.
4. Security analytics visualizations (Doughnut, OWASP Bar, Scan Timeline).
5. AI Security Analyst dedicated panel & strict offline fallback display.
6. Chronological security activity feed.
7. Recent scans table with status badges and action links.
8. Role-based visibility (Admin Panel visible to admins only).
9. API health endpoint preservation as pure JSON.
"""

import pytest
from app.models import db, User, Target, Scan, Vulnerability, Report
from app.models.vulnerability import AIAnalysis


@pytest.fixture
def soc_users(app):
    """Fixture providing standard analyst and admin user accounts."""
    with app.app_context():
        user = User(username="soc_analyst", email="analyst@soc.corp", role="USER")
        user.set_password("SecureAnalyst123!")
        admin = User(username="soc_admin", email="admin@soc.corp", role="ADMIN")
        admin.set_password("SecureAdmin1234!")
        db.session.add_all([user, admin])
        db.session.commit()
        return user.id, admin.id


def test_soc_dashboard_html_view_elements(client, soc_users):
    """Verify all enterprise SOC components render in the HTML dashboard."""
    u_id, _ = soc_users

    # Seed target and scan to verify table and populated state
    with client.application.app_context():
        t = Target(name="Acme Portal", target_url="https://acme.portal", domain="acme.portal", owner_id=u_id, is_verified=True, verification_status="VERIFIED")
        db.session.add(t)
        db.session.commit()

        s = Scan(target_id=t.id, user_id=u_id, scan_type="full", status="completed", total_vulnerabilities=2)
        db.session.add(s)
        db.session.commit()

    client.post("/auth/login", json={"login_id": "soc_analyst", "password": "SecureAnalyst123!"})

    resp = client.get("/dashboard")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")

    # 1. Branding & Navigation
    assert "AppSentinel" in html
    assert "v10.0-Final" in html
    assert "appSidebar" in html
    assert "Core Operations" in html
    assert "Vulnerability Assessment" in html
    assert "Intelligence & Reports" in html

    # 2. Four Primary KPI Cards
    assert "Total Targets" in html
    assert "Completed Scans" in html
    assert "Total Vulnerabilities" in html
    assert "Critical Vulnerabilities" in html

    # 3. Security Analytics Charts
    assert "severityDoughnutChart" in html
    assert "owaspBarChart" in html
    assert "scanActivityChart" in html

    # 4. AI Security Analyst Panel & Strict Offline Fallback Display
    assert "AI Security Analyst Subsystem" in html
    assert "Offline Security Analysis Active" in html

    # 5. Security Activity Feed
    assert "Security Activity Feed" in html

    # 6. Recent Scans Table Structure
    assert "Recent Security Scans" in html
    assert "Scan ID" in html
    assert "Completion Time" in html

    # 7. Quick Action Shortcuts
    assert "Add Target" in html
    assert "Start Scan" in html
    assert "AI Analyst" in html

    # 8. Topbar Controls
    assert "Engine Active" in html
    assert "globalSocSearch" in html


def test_soc_dashboard_admin_navigation_visibility(client, soc_users):
    """Verify Admin Panel link is visible to administrators and hidden from standard users."""
    u_id, a_id = soc_users

    # Standard User: Admin Panel link must NOT be visible
    client.post("/auth/login", json={"login_id": "soc_analyst", "password": "SecureAnalyst123!"})
    user_resp = client.get("/dashboard")
    assert "Admin Panel" not in user_resp.data.decode("utf-8")
    client.post("/auth/logout")

    # Admin User: Admin Panel link MUST be visible
    client.post("/auth/login", json={"login_id": "soc_admin", "password": "SecureAdmin1234!"})
    admin_resp = client.get("/dashboard")
    assert "Admin Panel" in admin_resp.data.decode("utf-8")


def test_soc_dashboard_unauthenticated_redirect(client):
    """Verify unauthenticated access redirects to login."""
    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code in (302, 401)


def test_api_health_endpoint_remains_json(client):
    """Strict Requirement: /api/health must remain a valid JSON monitoring endpoint."""
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert "application/json" in resp.headers["Content-Type"]
    data = resp.get_json()
    assert data["status"] == "healthy"
    assert "database" in data
    assert "timestamp" in data
