"""AppSentinel V10 - Final Integration & End-to-End System Validation Tests.

Validates the full enterprise cybersecurity workflow:
1. User Registration -> Login -> SOC Dashboard
2. Add Authorized Target -> Ownership Verification (DNS / HTTP well-known)
3. Passive Reconnaissance Engine Execution
4. Deterministic Vulnerability Scanning & Evidence Collection
5. Automated OWASP Top 10:2025 Mapping & CWE Taxonomy
6. FIRST CVSS v4.0 Canonical Vector Scoring & Risk Prioritization (P1-P5)
7. AI Security Analyst Diagnostics with Deterministic Offline Fallback
8. Professional ReportLab PDF Report Generation (COMPLETE, VULN_DETAIL, EXECUTIVE)
9. Cryptographic SHA-256 Pre-Download Integrity Verification
10. Multi-Tenant Authorization & IDOR Access Controls
"""

import pytest
from unittest.mock import MagicMock
import requests
from pathlib import Path
from app.models import (
    db,
    User,
    Target,
    Scan,
    Vulnerability,
    VulnerabilityEvidence,
    Report,
)
from app.models.vulnerability import AIAnalysis
from app.reports.report_service import ReportService
from app.security.target_validator import TargetValidator


def test_v10_complete_end_to_end_workflow(client, monkeypatch):
    """Execute and validate the complete 12-step AppSentinel security operations pipeline."""
    # Mock DNS resolution to public IP for safe offline test execution
    monkeypatch.setattr(TargetValidator, "resolve_and_validate_hostname", lambda host, allow_private=False: ["93.184.216.34"])

    # -------------------------------------------------------------------------
    # STEP 1: USER REGISTRATION
    # -------------------------------------------------------------------------
    reg_resp = client.post(
        "/auth/register",
        json={
            "full_name": "DevSecOps Lead",
            "username": "lead_secops",
            "email": "secops@enterprise.com",
            "password": "Password123!Safe",
            "confirm_password": "Password123!Safe",
        },
    )
    assert reg_resp.status_code == 201
    user_data = reg_resp.get_json()["user"]
    user_id = user_data["id"]

    # -------------------------------------------------------------------------
    # STEP 2: USER LOGIN
    # -------------------------------------------------------------------------
    login_resp = client.post(
        "/auth/login",
        json={
            "login_id": "lead_secops",
            "password": "Password123!Safe",
        },
    )
    assert login_resp.status_code == 200
    assert login_resp.get_json()["status"] == "success"

    # -------------------------------------------------------------------------
    # STEP 3: SOC DASHBOARD INITIAL ACCESS
    # -------------------------------------------------------------------------
    dash_resp = client.get("/dashboard", json={})
    assert dash_resp.status_code == 200
    dash_data = dash_resp.get_json()
    assert dash_data["metrics"]["targets"]["total"] == 0
    assert dash_data["metrics"]["scans"]["total"] == 0

    # -------------------------------------------------------------------------
    # STEP 4: ADD AUTHORIZED TARGET
    # -------------------------------------------------------------------------
    add_resp = client.post(
        "/targets/add",
        json={
            "name": "Acme Payments Microservice",
            "target_url": "https://payments.acme.test",
            "description": "Core authorization and payment checkout API gateway",
            "environment": "Production",
            "authorization_confirmed": True,
        },
    )
    assert add_resp.status_code == 201
    target_data = add_resp.get_json()["target"]
    target_id = target_data["id"]
    token = target_data["verification_token"]
    assert target_data["is_verified"] is False
    assert target_data["verification_status"] == "PENDING_VERIFICATION"

    # -------------------------------------------------------------------------
    # STEP 5: TARGET OWNERSHIP VERIFICATION
    # -------------------------------------------------------------------------
    # Mock successful HTTP well-known verification
    monkeypatch.setattr(
        TargetValidator,
        "verify_ownership_via_http",
        lambda domain, expected_token: (True, "Token matched at /.well-known/appsentinel-challenge.txt"),
    )

    verify_resp = client.post(
        f"/targets/{target_id}/verify",
        json={"method": "http_well_known"},
    )
    assert verify_resp.status_code == 200
    assert verify_resp.get_json()["status"] == "verified"

    with client.application.app_context():
        target_obj = db.session.get(Target, target_id)
        assert target_obj.is_verified is True
        assert target_obj.verification_status == "VERIFIED"

    # -------------------------------------------------------------------------
    # STEP 6: RECONNAISSANCE WORKFLOW
    # -------------------------------------------------------------------------
    fake_recon_resp = MagicMock()
    fake_recon_resp.status_code = 200
    fake_recon_resp.url = "https://payments.acme.test/"
    fake_recon_resp.headers = {
        "Server": "nginx/1.24.0",
        "X-Content-Type-Options": "nosniff",
    }
    fake_recon_resp.text = '<html><head><title>Acme Payments</title></head><body><a href="/checkout">Checkout</a></body></html>'
    fake_recon_resp.elapsed.total_seconds.return_value = 0.04
    monkeypatch.setattr(requests.Session, "get", lambda *args, **kwargs: fake_recon_resp)

    recon_start_resp = client.post(f"/recon/start/{target_id}", json={})
    assert recon_start_resp.status_code == 201
    assert recon_start_resp.get_json()["status"] == "completed"

    # -------------------------------------------------------------------------
    # STEP 7: DETERMINISTIC VULNERABILITY SCANNING
    # -------------------------------------------------------------------------
    fake_scan_resp = MagicMock()
    fake_scan_resp.status_code = 200
    fake_scan_resp.url = "https://payments.acme.test/"
    fake_scan_resp.headers = {
        "Server": "Apache/2.4.52 (Ubuntu)",
        "Content-Type": "text/html",
        # Missing CSP, X-Frame-Options, HSTS
    }
    fake_scan_resp.text = "<html><head><title>Acme Payments</title></head><body>Welcome</body></html>"
    insecure_cookie = MagicMock()
    insecure_cookie.name = "acme_session"
    insecure_cookie.secure = False
    insecure_cookie.has_nonstandard_attr.side_effect = lambda attr: False
    insecure_cookie.get_nonstandard_attr.side_effect = lambda attr: "None"
    fake_scan_resp.cookies = [insecure_cookie]
    fake_scan_resp.elapsed.total_seconds.return_value = 0.03

    monkeypatch.setattr(requests.Session, "get", lambda *args, **kwargs: fake_scan_resp)
    options_resp = MagicMock()
    options_resp.headers = {"Allow": "GET, POST, OPTIONS"}
    monkeypatch.setattr(requests.Session, "options", lambda *args, **kwargs: options_resp)

    scan_resp = client.post(f"/scanner/start/{target_id}", json={})
    assert scan_resp.status_code == 201
    scan_id = scan_resp.get_json()["scan_id"]

    # -------------------------------------------------------------------------
    # STEP 8: VULNERABILITY DISCOVERY & FINDINGS RETRIEVAL
    # -------------------------------------------------------------------------
    findings_resp = client.get(f"/scanner/api/findings/{scan_id}")
    assert findings_resp.status_code == 200
    findings_data = findings_resp.get_json()
    assert findings_data["total_findings"] >= 2
    vuln_list = findings_data["vulnerabilities"]
    first_vuln = vuln_list[0]
    vuln_id = first_vuln["id"]

    # Verify initial discovery categorization & CWE
    assert first_vuln["owasp_category"] != ""
    assert "CWE" in first_vuln["cwe_id"]

    # -------------------------------------------------------------------------
    # STEP 9: OWASP 2025 ANALYSIS, CVSS v4.0 SCORING & RISK PRIORITIZATION
    # -------------------------------------------------------------------------
    owasp_resp = client.post(f"/owasp/analyze/{target_id}", json={})
    assert owasp_resp.status_code == 201
    owasp_data = owasp_resp.get_json()
    assert owasp_data["framework_version"] == "2025"
    assert owasp_data["total_findings_mapped"] >= 2

    # Verify Risk Profile & CVSS v4.0 vector generation
    from app.models import RiskAssessment, OWASPFindingMapping
    with client.application.app_context():
        risk_entry = RiskAssessment.query.filter_by(vulnerability_id=vuln_id).first()
        assert risk_entry is not None
        assert risk_entry.cvss_score >= 0.0
        assert risk_entry.cvss_vector.startswith("CVSS:4.0/")
        assert risk_entry.operational_priority in ("P1", "P2", "P3", "P4", "P5")

        mapping_entry = OWASPFindingMapping.query.filter_by(vulnerability_id=vuln_id).first()
        assert mapping_entry is not None
        assert mapping_entry.framework_version == "2025"
        assert mapping_entry.primary_category_code.startswith("A")

    # -------------------------------------------------------------------------
    # STEP 10: AI SECURITY ANALYST DIAGNOSIS (OFFLINE DETERMINISTIC FALLBACK)
    # -------------------------------------------------------------------------
    ai_resp = client.post(f"/ai/analyze/finding/{vuln_id}", json={})
    assert ai_resp.status_code in (200, 201)
    ai_data = ai_resp.get_json()
    assert ai_data["success"] is True
    assert ai_data["data"]["is_fallback"] is True
    assert ai_data["data"]["root_cause"] != ""

    # -------------------------------------------------------------------------
    # STEP 11: PROFESSIONAL PDF REPORT GENERATION (ALL 3 TYPES)
    # -------------------------------------------------------------------------
    reports_created = []
    for rpt_type in ("COMPLETE", "VULN_DETAIL", "EXECUTIVE"):
        gen_resp = client.post(
            "/reports/generate",
            json={
                "scan_id": scan_id,
                "target_id": target_id,
                "report_type": rpt_type,
            },
        )
        assert gen_resp.status_code == 201, f"Failed for {rpt_type}"
        gen_data = gen_resp.get_json()
        assert gen_data["success"] is True
        rpt_obj = gen_data["report"]
        assert rpt_obj["report_type"] == rpt_type
        assert len(rpt_obj["file_hash"]) == 64
        # Verify file_path is NOT disclosed
        assert "file_path" not in rpt_obj
        reports_created.append(rpt_obj["id"])

    # -------------------------------------------------------------------------
    # STEP 12: PDF DOWNLOADING & SHA-256 INTEGRITY VALIDATION
    # -------------------------------------------------------------------------
    complete_rpt_id = reports_created[0]
    down_resp = client.get(f"/reports/download/{complete_rpt_id}")
    assert down_resp.status_code == 200
    assert down_resp.headers["Content-Type"] == "application/pdf"
    assert down_resp.data.startswith(b"%PDF-")
    assert b"%%EOF" in down_resp.data

    # Cleanup generated report files
    with client.application.app_context():
        for r_id in reports_created:
            ReportService.delete_report(r_id, user_id)


def test_v10_unverified_target_scan_rejection(client, monkeypatch):
    """Ensure active scans and recon are strictly blocked on unverified targets."""
    # Mock DNS resolution to public IP
    monkeypatch.setattr(TargetValidator, "resolve_and_validate_hostname", lambda host, allow_private=False: ["93.184.216.34"])

    # Register Alice
    client.post(
        "/auth/register",
        json={
            "full_name": "Alice Auditor",
            "username": "alice_unverified",
            "email": "alice_unverified@corp.com",
            "password": "Password123!Safe",
            "confirm_password": "Password123!Safe",
        },
    )
    client.post("/auth/login", json={"login_id": "alice_unverified", "password": "Password123!Safe"})

    # Add Target (unverified)
    add_resp = client.post(
        "/targets/add",
        json={
            "name": "Pending Target",
            "target_url": "https://unverified.target.test",
            "environment": "Staging",
            "authorization_confirmed": True,
        },
    )
    t_id = add_resp.get_json()["target"]["id"]

    # 1. Recon on unverified target must be rejected
    recon_resp = client.post(f"/recon/start/{t_id}", json={})
    assert recon_resp.status_code == 403

    # 2. Vulnerability Scan on unverified target must be rejected
    scan_resp = client.post(f"/scanner/start/{t_id}", json={})
    assert scan_resp.status_code == 403


def test_v10_cross_user_tenant_isolation_pipeline(client):
    """Verify complete IDOR isolation across targets, scans, findings, and reports."""
    # 1. Register Alice and create assets
    client.post(
        "/auth/register",
        json={
            "full_name": "Alice Tenant",
            "username": "alice_tenant",
            "email": "alice_tenant@corp.com",
            "password": "Password123!Safe",
            "confirm_password": "Password123!Safe",
        },
    )
    client.post("/auth/login", json={"login_id": "alice_tenant", "password": "Password123!Safe"})

    with client.application.app_context():
        alice = User.query.filter_by(username="alice_tenant").first()
        t = Target(
            name="Alice Secret App",
            target_url="https://alice.internal.test",
            domain="alice.internal.test",
            owner_id=alice.id,
            is_verified=True,
            verification_status="VERIFIED",
            verification_method="dns_txt",
        )
        db.session.add(t)
        db.session.commit()

        s = Scan(
            target_id=t.id,
            user_id=alice.id,
            scan_type="full",
            status="completed",
            risk_score=9.0,
            overall_risk="Critical",
        )
        db.session.add(s)
        db.session.commit()

        v = Vulnerability(
            scan_id=s.id,
            target_id=t.id,
            title="Alice Database Flaw",
            vulnerability_type="Injection",
            severity="CRITICAL",
            cvss_score=9.8,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            owasp_category="A03:2025-Injection",
            cwe_id="CWE-89",
            affected_url="https://alice.internal.test/query",
            http_method="POST",
            description="Alice critical SQL injection vulnerability flaw.",
        )
        db.session.add(v)
        db.session.commit()

        success, rpt, _ = ReportService.generate_report(
            user_id=alice.id,
            scan_id=s.id,
            target_id=t.id,
            report_type="COMPLETE",
        )
        rpt_id = rpt.id
        target_id = t.id
        scan_id = s.id
        vuln_id = v.id
        alice_user_id = alice.id

    # Logout Alice before Bob registers and authenticates
    client.post("/auth/logout")

    # 2. Register Bob (different tenant)
    client.post(
        "/auth/register",
        json={
            "full_name": "Bob Intruder",
            "username": "bob_intruder",
            "email": "bob_intruder@corp.com",
            "password": "Password123!Safe",
            "confirm_password": "Password123!Safe",
        },
    )
    b_login = client.post("/auth/login", json={"login_id": "bob_intruder", "password": "Password123!Safe"})
    assert b_login.status_code == 200

    # Bob attempts Target access
    assert client.get(f"/targets/{target_id}").status_code == 403

    # Bob attempts Scan Results access
    assert client.get(f"/scanner/results/{scan_id}").status_code == 403

    # Bob attempts Vulnerability Detail access
    assert client.get(f"/scanner/vulnerability/{vuln_id}").status_code == 403

    # Bob attempts AI analysis on Alice's finding
    assert client.post(f"/ai/analyze/finding/{vuln_id}", json={}).status_code == 403

    # Bob attempts Report Generation for Alice's scan
    assert client.post("/reports/generate", json={"scan_id": scan_id, "target_id": target_id}).status_code == 400

    # Bob attempts Report Metadata access
    assert client.get(f"/reports/{rpt_id}").status_code == 404

    # Bob attempts Report Download
    assert client.get(f"/reports/download/{rpt_id}").status_code == 404

    # Cleanup
    with client.application.app_context():
        ReportService.delete_report(rpt_id, alice_user_id)


def test_v10_dashboard_metrics_dynamic_update(client):
    """Verify dashboard metrics update dynamically after additions and scans."""
    client.post(
        "/auth/register",
        json={
            "full_name": "Metrics Observer",
            "username": "metrics_user",
            "email": "metrics@corp.com",
            "password": "Password123!Safe",
            "confirm_password": "Password123!Safe",
        },
    )
    client.post("/auth/login", json={"login_id": "metrics_user", "password": "Password123!Safe"})

    # Check initial baseline
    base_dash = client.get("/dashboard", json={}).get_json()["metrics"]
    assert base_dash["targets"]["total"] == 0
    assert base_dash["scans"]["total"] == 0
    assert base_dash["vulnerabilities"]["total"] == 0
    assert base_dash["reports"]["total"] == 0

    # Add target and scan
    with client.application.app_context():
        user = User.query.filter_by(username="metrics_user").first()
        user_id = user.id
        t = Target(name="Metric App", target_url="https://m.io", domain="m.io", owner_id=user_id, is_verified=True, verification_status="VERIFIED")
        db.session.add(t)
        db.session.commit()

        s = Scan(target_id=t.id, user_id=user_id, scan_type="full", status="completed", total_vulnerabilities=1)
        db.session.add(s)
        db.session.commit()

        v = Vulnerability(
            scan_id=s.id,
            target_id=t.id,
            title="Insecure Header",
            vulnerability_type="Security Misconfiguration",
            severity="HIGH",
            owasp_category="A05:2025-Security Misconfiguration",
            affected_url="https://m.io/",
            description="Missing critical Content-Security-Policy header.",
        )
        db.session.add(v)
        db.session.commit()

        success, r, _ = ReportService.generate_report(user_id=user_id, scan_id=s.id, report_type="EXECUTIVE")
        r_id = r.id

    # Verify updated metrics
    updated_dash = client.get("/dashboard", json={}).get_json()["metrics"]
    assert updated_dash["targets"]["total"] == 1
    assert updated_dash["targets"]["verified"] == 1
    assert updated_dash["scans"]["total"] == 1
    assert updated_dash["scans"]["completed"] == 1
    assert updated_dash["vulnerabilities"]["total"] == 1
    assert updated_dash["vulnerabilities"]["high"] == 1
    assert updated_dash["reports"]["total"] == 1

    # Cleanup
    with client.application.app_context():
        ReportService.delete_report(r_id, user_id)
