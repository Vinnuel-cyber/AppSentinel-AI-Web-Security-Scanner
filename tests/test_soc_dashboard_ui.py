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


def test_soc_dashboard_with_reports_and_null_hash(client, soc_users):
    """Regression Test: Dashboard rendering with reports having null file_hash and AI analysis records."""
    u_id, _ = soc_users
    with client.application.app_context():
        t = Target(name="Report Target", target_url="https://report.test", domain="report.test", owner_id=u_id, is_verified=True, verification_status="VERIFIED")
        db.session.add(t)
        db.session.commit()

        s = Scan(target_id=t.id, user_id=u_id, scan_type="full", status="completed", total_vulnerabilities=1)
        db.session.add(s)
        db.session.commit()

        # Report with None file_hash
        r1 = Report(scan_id=s.id, target_id=t.id, user_id=u_id, title="Test Null Hash Report", report_type="COMPLETE", file_path="reports/dummy.pdf", file_hash=None)
        # Report with valid file_hash
        r2 = Report(scan_id=s.id, target_id=t.id, user_id=u_id, title="Test Valid Hash Report", report_type="VULN_DETAIL", file_path="reports/dummy2.pdf", file_hash="abcdef0123456789")
        db.session.add_all([r1, r2])
        db.session.commit()

    client.post("/auth/login", json={"login_id": "soc_analyst", "password": "SecureAnalyst123!"})
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "Test Null Hash Report" in html
    assert "Test Valid Hash Report" in html
    assert "SHA-256: N/A" in html


def test_ai_analyst_page_with_unscored_findings(client, soc_users):
    """Regression Test: AI Security Analyst view handles unscored findings (cvss_score=None, affected_url=None)."""
    u_id, _ = soc_users
    with client.application.app_context():
        t = Target(name="AI Finding Target", target_url="https://ai.test", domain="ai.test", owner_id=u_id, is_verified=True, verification_status="VERIFIED")
        db.session.add(t)
        db.session.commit()

        s = Scan(target_id=t.id, user_id=u_id, scan_type="full", status="completed")
        db.session.add(s)
        db.session.commit()

        v1 = Vulnerability(scan_id=s.id, target_id=t.id, title="Unscored Vulnerability", vulnerability_type="misconfiguration", owasp_category="A05:2021 - Security Misconfiguration", description="Test unscored", severity="HIGH", cvss_score=None, affected_url="https://ai.test/unscored", status="open")
        v2 = Vulnerability(scan_id=s.id, target_id=t.id, title="Critical Scored Finding", vulnerability_type="sqli", owasp_category="A03:2021 - Injection", description="Test scored", severity="CRITICAL", cvss_score=9.5, affected_url="https://ai.test/api?v=1", status="open")
        db.session.add_all([v1, v2])
        db.session.commit()

    client.post("/auth/login", json={"login_id": "soc_analyst", "password": "SecureAnalyst123!"})
    resp = client.get("/ai")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "Unscored Vulnerability" in html
    assert "Critical Scored Finding" in html
    assert "N/A" in html

    # Test analyst workbench
    resp_workbench = client.get("/ai/analyst")
    assert resp_workbench.status_code == 200


def test_owasp_analyzer_page_and_navigation(client, soc_users):
    """Regression Test: OWASP Analyzer loads correctly with filters and links."""
    u_id, _ = soc_users
    with client.application.app_context():
        t = Target(name="OWASP Target", target_url="https://owasp.test", domain="owasp.test", owner_id=u_id, is_verified=True, verification_status="VERIFIED")
        db.session.add(t)
        db.session.commit()
        target_id = t.id

    client.post("/auth/login", json={"login_id": "soc_analyst", "password": "SecureAnalyst123!"})

    # Default 2025 view
    resp = client.get("/owasp")
    assert resp.status_code == 200
    assert "OWASP Top 10 Security Assessment" in resp.data.decode("utf-8")

    # 2021 view
    resp_2021 = client.get("/owasp?version=2021")
    assert resp_2021.status_code == 200

    # Assessment detail view
    resp_detail = client.get(f"/owasp/assessment/{target_id}")
    assert resp_detail.status_code == 200
    assert "OWASP Target" in resp_detail.data.decode("utf-8")


def test_reports_page_with_null_attributes(client, soc_users):
    """Regression Test: Reports page renders safely when report attributes are None."""
    u_id, _ = soc_users
    with client.application.app_context():
        t = Target(name="Rep Target", target_url="https://rep.test", domain="rep.test", owner_id=u_id, is_verified=True, verification_status="VERIFIED")
        db.session.add(t)
        db.session.commit()

        s = Scan(target_id=t.id, user_id=u_id, scan_type="full", status="completed")
        db.session.add(s)
        db.session.commit()

        r = Report(scan_id=s.id, target_id=t.id, user_id=u_id, title="Incomplete Report", report_type="EXECUTIVE", file_path="reports/inc.pdf", file_hash=None, file_size_bytes=None)
        db.session.add(r)
        db.session.commit()

    client.post("/auth/login", json={"login_id": "soc_analyst", "password": "SecureAnalyst123!"})
    resp = client.get("/reports")
    assert resp.status_code == 200
    assert "Incomplete Report" in resp.data.decode("utf-8")

