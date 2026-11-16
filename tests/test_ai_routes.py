"""AppSentinel AI Route & Endpoint Tests (V8)."""

import pytest
from app.models import db, User, Target, Scan, Vulnerability


@pytest.fixture
def ai_route_fixture(app):
    """Setup authenticated test user, verified target, and finding."""
    with app.app_context():
        user = User(username="route_tester", email="tester@ai.test", role="USER")
        user.set_password("Pass123456!")
        db.session.add(user)
        db.session.commit()

        target = Target(
            name="Route Test App",
            target_url="https://routetest.local",
            domain="routetest.local",
            owner_id=user.id,
            is_verified=True,
            verification_status="VERIFIED",
        )
        db.session.add(target)
        db.session.commit()

        scan = Scan(target_id=target.id, user_id=user.id, status="completed")
        db.session.add(scan)
        db.session.commit()

        vuln = Vulnerability(
            scan_id=scan.id,
            target_id=target.id,
            title="Reflected XSS in Comments",
            vulnerability_type="xss",
            severity="HIGH",
            confidence="HIGH",
            cvss_score=7.1,
            owasp_category="A03:2025-Injection",
            affected_url="https://routetest.local/comments?id=5",
            parameter="id",
            description="Payload reflected unescaped.",
        )
        db.session.add(vuln)
        db.session.commit()

        return user.id, target.id, vuln.id


def test_ai_routes_unauthenticated_redirect(client):
    """Verify unauthenticated requests are redirected or denied."""
    assert client.get("/ai", follow_redirects=False).status_code in (302, 401)
    assert client.get("/ai/analyst", follow_redirects=False).status_code in (302, 401)
    assert client.get("/ai/status", follow_redirects=False).status_code in (302, 401)
    assert client.post("/ai/analyze/finding/1").status_code in (302, 401)
    assert client.post("/ai/chat", json={"query": "test"}).status_code in (302, 401)


def test_ai_status_endpoint(client, ai_route_fixture):
    """Verify /ai/status returns valid JSON telemetry."""
    client.post("/auth/login", json={"login_id": "route_tester", "password": "Pass123456!"})
    resp = client.get("/ai/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "ai_enabled" in data
    assert "provider" in data
    assert "fallback_engine" in data


def test_ai_dashboard_and_workbench_views(client, ai_route_fixture):
    """Verify HTML dashboard and workbench render 200 OK for logged-in user."""
    client.post("/auth/login", json={"login_id": "route_tester", "password": "Pass123456!"})
    resp1 = client.get("/ai/")
    assert resp1.status_code == 200
    assert b"AI Security Analyst SOC" in resp1.data

    resp2 = client.get("/ai/analyst")
    assert resp2.status_code == 200
    assert b"Security Analyst Interactive Workbench" in resp2.data


def test_ai_analyze_finding_endpoint(client, ai_route_fixture):
    """Verify POST /ai/analyze/finding/<id> executes analysis and returns JSON."""
    user_id, target_id, vuln_id = ai_route_fixture
    client.post("/auth/login", json={"login_id": "route_tester", "password": "Pass123456!"})

    resp = client.post(f"/ai/analyze/finding/{vuln_id}", json={})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert "data" in data
    assert data["data"]["analysis_type"] == "vulnerability_explanation"


def test_ai_analyze_target_endpoint(client, ai_route_fixture):
    """Verify POST /ai/analyze/target/<id> returns posture assessment."""
    user_id, target_id, vuln_id = ai_route_fixture
    client.post("/auth/login", json={"login_id": "route_tester", "password": "Pass123456!"})

    resp = client.post(f"/ai/analyze/target/{target_id}", json={})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert data["data"]["analysis_type"] == "target_summary"


def test_ai_chat_lifecycle(client, ai_route_fixture):
    """Verify conversational Q&A, transcript retrieval, and conversation deletion."""
    user_id, target_id, vuln_id = ai_route_fixture
    client.post("/auth/login", json={"login_id": "route_tester", "password": "Pass123456!"})

    # 1. Send chat message
    chat_resp = client.post("/ai/chat", json={
        "query": "How do I secure the comments endpoint against XSS?",
        "target_id": target_id,
    })
    assert chat_resp.status_code == 200
    chat_data = chat_resp.get_json()
    assert chat_data["success"] is True
    conv_id = chat_data["conversation_id"]
    assert conv_id is not None

    # 2. List conversations
    convs_resp = client.get("/ai/conversations")
    assert convs_resp.status_code == 200
    conv_list = convs_resp.get_json()["conversations"]
    assert len(conv_list) >= 1
    assert conv_list[0]["id"] == conv_id

    # 3. Get transcript
    transcript_resp = client.get(f"/ai/conversation/{conv_id}")
    assert transcript_resp.status_code == 200
    messages = transcript_resp.get_json()["messages"]
    assert len(messages) == 2  # user + assistant

    # 4. Delete conversation
    del_resp = client.delete(f"/ai/conversation/{conv_id}")
    assert del_resp.status_code == 200
    assert del_resp.get_json()["success"] is True

    # 5. Verify deleted
    assert client.get(f"/ai/conversation/{conv_id}").status_code == 404
