"""AppSentinel AI Multi-Tenant Authorization & RBAC Isolation Tests (V8)."""

import pytest
from app.models import db, User, Target, Scan, Vulnerability
from app.models.ai import AIConversation, AIMessage


@pytest.fixture
def multi_tenant_fixture(app):
    """Setup Alice (Owner), Bob (Attacker/Separate Tenant), and Carol (Admin)."""
    with app.app_context():
        alice = User(username="alice_tenant", email="alice@corp.test", role="USER")
        alice.set_password("AliceSecure123!")
        bob = User(username="bob_tenant", email="bob@corp.test", role="USER")
        bob.set_password("BobSecure1234!")
        carol = User(username="carol_admin", email="carol@corp.test", role="ADMIN")
        carol.set_password("CarolSecure123!")
        db.session.add_all([alice, bob, carol])
        db.session.commit()

        # Alice's target & finding
        alice_target = Target(
            name="Alice Production API",
            target_url="https://api.alice.test",
            domain="api.alice.test",
            owner_id=alice.id,
            is_verified=True,
            verification_status="VERIFIED",
        )
        db.session.add(alice_target)
        db.session.commit()

        alice_scan = Scan(target_id=alice_target.id, user_id=alice.id, status="completed")
        db.session.add(alice_scan)
        db.session.commit()

        alice_vuln = Vulnerability(
            scan_id=alice_scan.id,
            target_id=alice_target.id,
            title="Alice Internal Secret Leak",
            vulnerability_type="info_disclosure",
            severity="HIGH",
            cvss_score=7.5,
            owasp_category="A01:2025-Broken Access Control",
            affected_url="https://api.alice.test/debug/vars",
            description="Exposed internal debug variables leaking sensitive runtime state.",
        )
        db.session.add(alice_vuln)
        db.session.commit()

        # Alice's conversation
        alice_conv = AIConversation(
            user_id=alice.id,
            target_id=alice_target.id,
            title="Alice Private Session",
        )
        db.session.add(alice_conv)
        db.session.commit()

        return {
            "alice_id": alice.id,
            "bob_id": bob.id,
            "carol_id": carol.id,
            "alice_target_id": alice_target.id,
            "alice_vuln_id": alice_vuln.id,
            "alice_conv_id": alice_conv.id,
        }


def test_cross_user_finding_analysis_blocked(client, multi_tenant_fixture):
    """Verify Bob cannot trigger AI analysis on Alice's vulnerability finding."""
    vuln_id = multi_tenant_fixture["alice_vuln_id"]
    # Login as Bob
    client.post("/auth/login", json={"login_id": "bob_tenant", "password": "BobSecure1234!"})

    resp = client.post(f"/ai/analyze/finding/{vuln_id}", json={})
    assert resp.status_code == 403
    assert b"unauthorized" in resp.data.lower() or b"forbidden" in resp.data.lower()


def test_cross_user_target_posture_blocked(client, multi_tenant_fixture):
    """Verify Bob cannot analyze posture of Alice's target application."""
    target_id = multi_tenant_fixture["alice_target_id"]
    # Login as Bob
    client.post("/auth/login", json={"login_id": "bob_tenant", "password": "BobSecure1234!"})

    resp = client.post(f"/ai/analyze/target/{target_id}", json={})
    assert resp.status_code == 403


def test_cross_user_chat_scope_blocked(client, multi_tenant_fixture):
    """Verify Bob cannot scope security chat to Alice's target."""
    target_id = multi_tenant_fixture["alice_target_id"]
    # Login as Bob
    client.post("/auth/login", json={"login_id": "bob_tenant", "password": "BobSecure1234!"})

    resp = client.post("/ai/chat", json={
        "query": "Tell me secrets about this target",
        "target_id": target_id,
    })
    assert resp.status_code == 400
    assert b"Unauthorized target scope" in resp.data


def test_cross_user_conversation_transcript_blocked(client, multi_tenant_fixture):
    """Verify Bob cannot view Alice's conversation transcript."""
    conv_id = multi_tenant_fixture["alice_conv_id"]
    # Login as Bob
    client.post("/auth/login", json={"login_id": "bob_tenant", "password": "BobSecure1234!"})

    resp = client.get(f"/ai/conversation/{conv_id}")
    assert resp.status_code == 404

    del_resp = client.delete(f"/ai/conversation/{conv_id}")
    assert del_resp.status_code == 404


def test_admin_authorized_access(client, multi_tenant_fixture):
    """Verify Admin Carol can access and analyze Alice's target and finding."""
    vuln_id = multi_tenant_fixture["alice_vuln_id"]
    target_id = multi_tenant_fixture["alice_target_id"]

    # Login as Carol (Admin)
    client.post("/auth/login", json={"login_id": "carol_admin", "password": "CarolSecure123!"})

    resp_find = client.post(f"/ai/analyze/finding/{vuln_id}", json={})
    assert resp_find.status_code == 200
    assert resp_find.get_json()["success"] is True

    resp_tgt = client.post(f"/ai/analyze/target/{target_id}", json={})
    assert resp_tgt.status_code == 200
    assert resp_tgt.get_json()["success"] is True
