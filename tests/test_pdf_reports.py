"""AppSentinel Professional PDF Report Generator Tests (V9)."""

import os
from pathlib import Path
import pytest
from app.models import (
    db,
    User,
    Target,
    Scan,
    Vulnerability,
    VulnerabilityEvidence,
    Report,
    SecurityReport,
)
from app.models.vulnerability import AIAnalysis
from app.reports.report_service import ReportService
from app.reports.pdf_theme import PDFTheme
from app.reports.data_collector import SecurityDataCollector


@pytest.fixture
def pdf_test_context(app):
    """Fixture creating Alice (Target Owner), Bob (Other Tenant), and Carol (Admin)."""
    with app.app_context():
        alice = User(username="alice_pdf", email="alice@pdf.test", role="USER")
        alice.set_password("AliceSecure123!")
        bob = User(username="bob_pdf", email="bob@pdf.test", role="USER")
        bob.set_password("BobSecure1234!")
        carol = User(username="carol_admin_pdf", email="carol@pdf.test", role="ADMIN")
        carol.set_password("CarolSecure123!")
        db.session.add_all([alice, bob, carol])
        db.session.commit()

        target = Target(
            name="Alice Banking Portal",
            target_url="https://bank.alice.test",
            domain="bank.alice.test",
            owner_id=alice.id,
            environment="Production",
            is_verified=True,
            verification_status="VERIFIED",
            verification_method="dns_txt",
        )
        db.session.add(target)
        db.session.commit()

        scan = Scan(
            target_id=target.id,
            user_id=alice.id,
            scan_type="full",
            status="completed",
            risk_score=8.5,
            overall_risk="High",
            total_vulnerabilities=2,
            duration_seconds=42,
        )
        db.session.add(scan)
        db.session.commit()

        # Vuln 1: Critical SQL Injection with evidence and AI analysis
        v1 = Vulnerability(
            scan_id=scan.id,
            target_id=target.id,
            title="SQL Injection in Login Endpoint",
            vulnerability_type="sqli",
            severity="CRITICAL",
            confidence="CONFIRMED",
            cvss_score=9.8,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            owasp_category="A03:2025-Injection",
            cwe_id="CWE-89",
            affected_url="https://bank.alice.test/api/login",
            parameter="username",
            http_method="POST",
            description="Dynamic SQL query concatenation allows arbitrary database syntax execution.",
            remediation="Use parameterized queries via SQLAlchemy ORM.",
        )
        db.session.add(v1)
        db.session.commit()

        ev1 = VulnerabilityEvidence(
            vulnerability_id=v1.id,
            payload="' OR '1'='1",
            evidence_snippet="SyntaxError: You have an error in your SQL syntax near '1'='1'",
            request_dump="POST /api/login HTTP/1.1\nHost: bank.alice.test\n\nusername=' OR '1'='1",
            response_dump="HTTP/1.1 500 Internal Server Error\nContent-Type: text/html",
        )
        db.session.add(ev1)

        ai1 = AIAnalysis(
            vulnerability_id=v1.id,
            target_id=target.id,
            user_id=alice.id,
            analysis_type="vulnerability_explanation",
            provider="deterministic-fallback",
            model_name="rule-engine-v1",
            status="COMPLETED",
            ai_confidence="HIGH",
            explanation="The login handler concatenates input directly into SQL strings without parameter binding.",
            potential_impact="Complete database compromise and administrative account takeover.",
            root_cause="Improper query parameter binding.",
            recommended_remediation="Refactor to use bound parameters.",
            secure_coding_example="db.session.execute(text('SELECT * FROM users WHERE u=:u'), {'u': username})",
            is_fallback=True,
        )
        db.session.add(ai1)

        # Vuln 2: High Reflected XSS without AI analysis
        v2 = Vulnerability(
            scan_id=scan.id,
            target_id=target.id,
            title="Reflected XSS in Search Query",
            vulnerability_type="xss",
            severity="HIGH",
            confidence="HIGH",
            cvss_score=7.5,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
            owasp_category="A03:2025-Injection",
            cwe_id="CWE-79",
            affected_url="https://bank.alice.test/search",
            parameter="q",
            http_method="GET",
            description="Query parameter reflected unencoded in response DOM.",
            remediation="Contextual output encoding and defensive CSP header.",
        )
        db.session.add(v2)
        db.session.commit()

        # Empty scan for edge case testing
        empty_scan = Scan(
            target_id=target.id,
            user_id=alice.id,
            scan_type="passive",
            status="completed",
            risk_score=0.0,
            overall_risk="Informational",
            total_vulnerabilities=0,
        )
        db.session.add(empty_scan)
        db.session.commit()

        return {
            "alice_id": alice.id,
            "bob_id": bob.id,
            "carol_id": carol.id,
            "target_id": target.id,
            "scan_id": scan.id,
            "empty_scan_id": empty_scan.id,
            "v1_id": v1.id,
            "v2_id": v2.id,
        }


def test_pdf_theme_styles():
    """Verify theme styles and severity color mappings."""
    styles = PDFTheme.get_stylesheet()
    assert "CoverTitle" in styles
    assert "ReportH1" in styles
    assert "TableCellBold" in styles

    assert PDFTheme.get_severity_color("CRITICAL") == PDFTheme.CRITICAL
    assert PDFTheme.get_severity_color("HIGH") == PDFTheme.HIGH
    assert PDFTheme.get_severity_color("MEDIUM") == PDFTheme.MEDIUM
    assert PDFTheme.get_severity_color("LOW") == PDFTheme.LOW
    assert PDFTheme.get_severity_color("UNKNOWN") == PDFTheme.INFO


def test_generate_complete_assessment_report(client, pdf_test_context):
    """Verify generation of Complete Security Assessment Report (PDF bytes, storage, hash)."""
    ctx = pdf_test_context
    with client.application.app_context():
        success, report, msg = ReportService.generate_report(
            user_id=ctx["alice_id"],
            scan_id=ctx["scan_id"],
            target_id=ctx["target_id"],
            report_type="COMPLETE",
        )

        assert success is True
        assert report is not None
        assert report.report_type == "COMPLETE"
        assert report.file_format == "PDF"
        assert report.file_size_bytes > 5000
        assert len(report.file_hash) == 64  # SHA-256 hex string

        # Verify file exists on disk and is a valid PDF
        file_path = Path(report.file_path)
        assert file_path.exists()
        with open(file_path, "rb") as f:
            header = f.read(5)
            assert header == b"%PDF-"

        # Cleanup test file
        if file_path.exists():
            file_path.unlink()


def test_generate_vulnerability_detail_report(client, pdf_test_context):
    """Verify generation of Vulnerability Detail Report."""
    ctx = pdf_test_context
    with client.application.app_context():
        success, report, msg = ReportService.generate_report(
            user_id=ctx["alice_id"],
            scan_id=ctx["scan_id"],
            target_id=ctx["target_id"],
            report_type="VULN_DETAIL",
        )

        assert success is True
        assert report.report_type == "VULN_DETAIL"
        assert report.file_size_bytes > 0

        file_path = Path(report.file_path)
        assert file_path.exists()
        file_path.unlink()


def test_generate_executive_summary_report(client, pdf_test_context):
    """Verify generation of Executive Summary Report."""
    ctx = pdf_test_context
    with client.application.app_context():
        success, report, msg = ReportService.generate_report(
            user_id=ctx["alice_id"],
            scan_id=ctx["scan_id"],
            target_id=ctx["target_id"],
            report_type="EXECUTIVE",
        )

        assert success is True
        assert report.report_type == "EXECUTIVE"
        assert report.file_size_bytes > 0

        file_path = Path(report.file_path)
        assert file_path.exists()
        file_path.unlink()


def test_generate_report_empty_scan(client, pdf_test_context):
    """Verify empty scan (0 findings) compiles without layout errors."""
    ctx = pdf_test_context
    with client.application.app_context():
        success, report, msg = ReportService.generate_report(
            user_id=ctx["alice_id"],
            scan_id=ctx["empty_scan_id"],
            target_id=ctx["target_id"],
            report_type="COMPLETE",
        )

        assert success is True
        assert report.file_size_bytes > 0
        file_path = Path(report.file_path)
        assert file_path.exists()
        file_path.unlink()


def test_report_routes_and_download(client, pdf_test_context):
    """Verify API generation, history retrieval, and secure download."""
    ctx = pdf_test_context
    # Login as Alice
    client.post("/auth/login", json={"login_id": "alice_pdf", "password": "AliceSecure123!"})

    # 1. Generate via POST endpoint
    gen_resp = client.post("/reports/generate", json={
        "scan_id": ctx["scan_id"],
        "target_id": ctx["target_id"],
        "report_type": "COMPLETE",
    })
    assert gen_resp.status_code == 201
    data = gen_resp.get_json()
    assert data["success"] is True
    report_id = data["report"]["id"]

    # 2. View History
    hist_resp = client.get("/reports/history")
    assert hist_resp.status_code == 200
    reports_list = hist_resp.get_json()["reports"]
    assert any(r["id"] == report_id for r in reports_list)

    # 3. Download Report
    down_resp = client.get(f"/reports/download/{report_id}")
    assert down_resp.status_code == 200
    assert down_resp.headers["Content-Type"] == "application/pdf"
    assert down_resp.data.startswith(b"%PDF-")

    # 4. Delete Report
    del_resp = client.delete(f"/reports/{report_id}")
    assert del_resp.status_code == 200
    assert del_resp.get_json()["success"] is True


def test_report_cross_user_download_forbidden(client, pdf_test_context):
    """Verify Bob cannot download Alice's security report (IDOR defense)."""
    ctx = pdf_test_context
    with client.application.app_context():
        success, report, _ = ReportService.generate_report(
            user_id=ctx["alice_id"],
            scan_id=ctx["scan_id"],
            target_id=ctx["target_id"],
            report_type="COMPLETE",
        )
        report_id = report.id

    # Login as Bob
    client.post("/auth/login", json={"login_id": "bob_pdf", "password": "BobSecure1234!"})

    # Bob attempts download
    down_resp = client.get(f"/reports/download/{report_id}")
    assert down_resp.status_code == 404
    assert b"Unauthorized" in down_resp.data or b"Not Found" in down_resp.data

    # Bob attempts delete
    del_resp = client.delete(f"/reports/{report_id}")
    assert del_resp.status_code == 404

    # Cleanup
    with client.application.app_context():
        ReportService.delete_report(report_id, ctx["alice_id"])


def test_path_traversal_defense(client):
    """Verify Path traversal attempts are rejected by is_safe_path."""
    storage_dir = ReportService.get_report_storage_dir()
    malicious_path = storage_dir / ".." / ".." / "etc" / "passwd"

    assert ReportService.is_safe_path(malicious_path, storage_dir) is False

    valid_path = storage_dir / "safe_report.pdf"
    assert ReportService.is_safe_path(valid_path, storage_dir) is True


def test_admin_can_access_all_reports(client, pdf_test_context):
    """Verify Admin Carol can view and download Alice's report."""
    ctx = pdf_test_context
    with client.application.app_context():
        success, report, _ = ReportService.generate_report(
            user_id=ctx["alice_id"],
            scan_id=ctx["scan_id"],
            target_id=ctx["target_id"],
            report_type="EXECUTIVE",
        )
        report_id = report.id

    # Login as Admin Carol
    client.post("/auth/login", json={"login_id": "carol_admin_pdf", "password": "CarolSecure123!"})

    down_resp = client.get(f"/reports/download/{report_id}")
    assert down_resp.status_code == 200
    assert down_resp.data.startswith(b"%PDF-")

    # Cleanup
    with client.application.app_context():
        ReportService.delete_report(report_id, ctx["carol_id"], is_admin=True)


def test_invalid_report_type_rejected(client, pdf_test_context):
    """Verify invalid report type strings are rejected with 400 Bad Request."""
    ctx = pdf_test_context
    client.post("/auth/login", json={"login_id": "alice_pdf", "password": "AliceSecure123!"})

    resp = client.post("/reports/generate", json={
        "scan_id": ctx["scan_id"],
        "report_type": "HACKER_EXPLOIT_LEAK",
    })
    assert resp.status_code == 400
    assert "Invalid report type" in resp.get_json()["message"]


def test_reports_status_endpoint(client):
    """Verify /reports/status returns valid JSON telemetry."""
    resp = client.get("/reports/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["module"] == "Report Generator"
    assert data["version"] == "V9"
    assert "ReportLab" in data["engine"]


def test_evidence_secret_redaction_in_data_collector(client, pdf_test_context):
    """Verify sensitive tokens and keys in evidence are redacted prior to PDF generation."""
    ctx = pdf_test_context
    with client.application.app_context():
        # Inject sensitive AWS key into evidence
        ev = VulnerabilityEvidence.query.filter_by(vulnerability_id=ctx["v1_id"]).first()
        ev.payload = "AKIAIOSFODNN7EXAMPLE' OR 1=1--"
        db.session.commit()

        data = SecurityDataCollector.collect_assessment_data(scan_id=ctx["scan_id"])
        finding = data["findings"][0]
        evidence = finding["evidence_list"][0]

        assert "AKIAIOSFODNN7EXAMPLE" not in evidence["payload"]
        assert "[REDACTED_AWS_KEY]" in evidence["payload"]


def test_reports_dashboard_view_html(client, pdf_test_context):
    """Verify HTML Report Center dashboard renders 200 OK for authenticated user."""
    client.post("/auth/login", json={"login_id": "alice_pdf", "password": "AliceSecure123!"})
    resp = client.get("/reports/")
    assert resp.status_code == 200
    assert b"Professional Report Center" in resp.data
    assert b"Generate New Report" in resp.data


def test_missing_ai_analysis_handled_gracefully(client, pdf_test_context):
    """Verify vulnerability without AI analysis record compiles cleanly with deterministic fallback."""
    ctx = pdf_test_context
    with client.application.app_context():
        # Vuln 2 has no AIAnalysis record
        data = SecurityDataCollector.collect_assessment_data(scan_id=ctx["scan_id"])
        v2_data = [f for f in data["findings"] if f["id"] == ctx["v2_id"]][0]
        assert v2_data["ai_analysis"] is None
        assert v2_data["remediation"] != ""

        # Generating report works cleanly
        success, report, _ = ReportService.generate_report(
            user_id=ctx["alice_id"],
            scan_id=ctx["scan_id"],
            report_type="COMPLETE",
        )
        assert success is True
        file_path = Path(report.file_path)
        assert file_path.exists()
        file_path.unlink()
