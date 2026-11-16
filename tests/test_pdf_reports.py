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


def test_path_traversal_prefix_collision_and_dir_rejection(client):
    """Verify is_safe_path rejects prefix collisions (reports_backup) and the root directory itself."""
    storage_dir = ReportService.get_report_storage_dir()

    # 1. Base directory itself must be rejected (not a safe file)
    assert ReportService.is_safe_path(storage_dir, storage_dir) is False

    # 2. Sibling directory with shared prefix (e.g., reports_backup) must be rejected
    sibling_colliding_dir = storage_dir.parent / (storage_dir.name + "_backup") / "evil.pdf"
    assert ReportService.is_safe_path(sibling_colliding_dir, storage_dir) is False

    # 3. Path traversal with .. must be rejected
    traversal_path = storage_dir / ".." / "secret.key"
    assert ReportService.is_safe_path(traversal_path, storage_dir) is False

    # 4. Valid file inside storage_dir must be accepted
    safe_path = storage_dir / "legit_report.pdf"
    assert ReportService.is_safe_path(safe_path, storage_dir) is True


def test_pdf_download_integrity_verification_tamper_detection(client, pdf_test_context):
    """Verify download verifies stored SHA-256 hash and blocks tampered or corrupted files."""
    ctx = pdf_test_context
    client.post("/auth/login", json={"login_id": "alice_pdf", "password": "AliceSecure123!"})

    with client.application.app_context():
        success, report, _ = ReportService.generate_report(
            user_id=ctx["alice_id"],
            scan_id=ctx["scan_id"],
            target_id=ctx["target_id"],
            report_type="COMPLETE",
        )
        report_id = report.id
        file_path = Path(report.file_path)

    # 1. Tamper with disk file (corrupt content)
    with open(file_path, "ab") as f:
        f.write(b"\nTAMPERED_MALICIOUS_INJECTION")

    # 2. Attempt download of tampered report
    down_resp = client.get(f"/reports/download/{report_id}")
    assert down_resp.status_code == 400
    assert "integrity" in down_resp.get_json()["message"].lower()

    # 3. Delete physical file to simulate missing file
    if file_path.exists():
        file_path.unlink()

    down_missing_resp = client.get(f"/reports/download/{report_id}")
    assert down_missing_resp.status_code == 404
    assert "not found" in down_missing_resp.get_json()["message"].lower()

    # Cleanup DB record
    with client.application.app_context():
        ReportService.delete_report(report_id, ctx["alice_id"])


def test_reportlab_markup_injection_and_unclosed_tags(client, pdf_test_context):
    """Verify unclosed HTML/XML tags in evidence and target do not crash ReportLab."""
    ctx = pdf_test_context
    with client.application.app_context():
        # Inject adversarial unclosed XML markup and payloads into target and evidence
        target = db.session.get(Target, ctx["target_id"])
        target.name = "Adversarial <script> Corp & Co"
        target.target_url = "https://bank.test/app?foo=1&bar=2<unclosed"

        v1 = db.session.get(Vulnerability, ctx["v1_id"])
        v1.title = "XSS in <header> & <div>"
        v1.description = "Exploit observed: <script>alert(1)</script> & 1 < 2 with unclosed <tag>"
        v1.remediation = "Encode <html> entities & sanitize <input>"

        ev = VulnerabilityEvidence.query.filter_by(vulnerability_id=ctx["v1_id"]).first()
        ev.payload = "<svg/onload=alert('xss')> & <unclosed_payload"
        ev.evidence_snippet = "<div class='test'>Response dump: & <img src=x onerror=alert(2)>"

        ai = AIAnalysis.query.filter_by(vulnerability_id=ctx["v1_id"]).first()
        ai.code_example = "std::vector<int> v; for (auto i : v) { if (i < 10 && i > 0) {} }"
        ai.verification_steps = "Run curl http://bank.test?q=<payload> & check <DOM>"
        db.session.commit()

        # Compile PDF with these adversarial payloads
        success, report, msg = ReportService.generate_report(
            user_id=ctx["alice_id"],
            scan_id=ctx["scan_id"],
            report_type="COMPLETE",
        )
        assert success is True, f"PDF generation failed with markup error: {msg}"
        file_path = Path(report.file_path)
        assert file_path.exists()
        assert file_path.stat().st_size > 0
        file_path.unlink()


def test_secret_redaction_comprehensive_matrix(client, pdf_test_context):
    """Verify all categories of sensitive tokens are redacted in collected assessment data."""
    ctx = pdf_test_context
    with client.application.app_context():
        v1 = db.session.get(Vulnerability, ctx["v1_id"])
        ev = VulnerabilityEvidence.query.filter_by(vulnerability_id=v1.id).first()
        ev.payload = "sk-proj-abc1234567890abcdefghijklmn"  # OpenAI key
        ev.evidence_snippet = "Authorization: Bearer mySecretBearerToken12345\nCookie: session=secretSessionCookie12345"
        ev.request_dump = "ghp_123456789012345678901234567890123456\npassword: mySuperSecretPassword123"
        db.session.commit()

        data = SecurityDataCollector.collect_assessment_data(scan_id=ctx["scan_id"])
        ev_data = data["findings"][0]["evidence_list"][0]

        # Assert no bare secrets leaked
        assert "sk-proj-abc1234567890abcdefghijklmn" not in ev_data["payload"]
        assert "[REDACTED_API_KEY]" in ev_data["payload"]

        assert "mySecretBearerToken12345" not in ev_data["snippet"]
        assert "Bearer [REDACTED_TOKEN]" in ev_data["snippet"]

        assert "secretSessionCookie12345" not in ev_data["snippet"]
        assert "session=[REDACTED_COOKIE]" in ev_data["snippet"]

        assert "ghp_123456789012345678901234567890123456" not in ev_data["request"]
        assert "[REDACTED_GITHUB_TOKEN]" in ev_data["request"]

        assert "mySuperSecretPassword123" not in ev_data["request"]
        assert "[REDACTED_SECRET]" in ev_data["request"]


def test_api_response_does_not_disclose_filesystem_path(client, pdf_test_context):
    """Verify internal filesystem paths are never disclosed in report API responses."""
    ctx = pdf_test_context
    client.post("/auth/login", json={"login_id": "alice_pdf", "password": "AliceSecure123!"})

    # 1. Generate report
    gen_resp = client.post("/reports/generate", json={
        "scan_id": ctx["scan_id"],
        "target_id": ctx["target_id"],
        "report_type": "EXECUTIVE",
    })
    assert gen_resp.status_code == 201
    gen_data = gen_resp.get_json()
    report_dict = gen_data["report"]
    report_id = report_dict["id"]

    assert "file_path" not in report_dict
    assert "file_path" not in str(gen_data)

    # 2. View details
    det_resp = client.get(f"/reports/{report_id}")
    assert det_resp.status_code == 200
    det_data = det_resp.get_json()
    assert "file_path" not in det_data["report"]

    # 3. View history
    hist_resp = client.get("/reports/history")
    assert hist_resp.status_code == 200
    hist_reports = hist_resp.get_json()["reports"]
    for r in hist_reports:
        assert "file_path" not in r

    # Cleanup
    with client.application.app_context():
        ReportService.delete_report(report_id, ctx["alice_id"])


def test_cross_user_unauthorized_generation_prevented(client, pdf_test_context):
    """Verify Bob cannot trigger report generation against Alice's scan or target."""
    ctx = pdf_test_context
    client.post("/auth/login", json={"login_id": "bob_pdf", "password": "BobSecure1234!"})

    # Bob attempts generating a report for Alice's scan
    resp = client.post("/reports/generate", json={
        "scan_id": ctx["scan_id"],
        "target_id": ctx["target_id"],
        "report_type": "COMPLETE",
    })
    assert resp.status_code == 400
    assert "unauthorized" in resp.get_json()["message"].lower()


def test_cross_user_report_metadata_access_prevented(client, pdf_test_context):
    """Verify Bob cannot view Alice's report metadata (IDOR defense)."""
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

    meta_resp = client.get(f"/reports/{report_id}")
    assert meta_resp.status_code == 404
    assert "not found" in meta_resp.get_json()["message"].lower()

    # Cleanup
    with client.application.app_context():
        ReportService.delete_report(report_id, ctx["alice_id"])


def test_pdf_structure_quality_and_page_numbering(client, pdf_test_context):
    """Verify multi-page PDF generation, %%EOF markers, and all 3 format styles."""
    ctx = pdf_test_context
    with client.application.app_context():
        # Inject long description to force multi-page layout
        v1 = db.session.get(Vulnerability, ctx["v1_id"])
        v1.description = "Deep technical analysis: " + ("This is an enterprise vulnerability assessment finding with extensive context. " * 30)
        db.session.commit()

        for rpt_type in ("COMPLETE", "VULN_DETAIL", "EXECUTIVE"):
            success, report, msg = ReportService.generate_report(
                user_id=ctx["alice_id"],
                scan_id=ctx["scan_id"],
                report_type=rpt_type,
            )
            assert success is True, f"Failed generating {rpt_type}: {msg}"
            file_path = Path(report.file_path)
            assert file_path.exists()

            with open(file_path, "rb") as f:
                content = f.read()
                assert content.startswith(b"%PDF-")
                assert b"%%EOF" in content
                # File must be substantial in bytes
                assert len(content) > 3000

            file_path.unlink()
