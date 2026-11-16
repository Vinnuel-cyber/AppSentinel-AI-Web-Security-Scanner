import pytest
from app.models import (
    db,
    User,
    Target,
    Scan,
    ScanURL,
    ScanLog,
    ScanSetting,
    Vulnerability,
    VulnerabilityEvidence,
    AIAnalysis,
    Report,
)


def test_user_creation_and_hashing(app):
    """Verify User model password hashing and role validation."""
    with app.app_context():
        user = User(username="secops_lead", email="lead@appsentinel.io", role="admin")
        user.set_password("StrongP@ssw0rd2026!")
        db.session.add(user)
        db.session.commit()

        queried = User.query.filter_by(username="secops_lead").first()
        assert queried is not None
        assert queried.check_password("StrongP@ssw0rd2026!") is True
        assert queried.check_password("WrongPassword") is False
        assert queried.is_admin() is True
        assert queried.password_hash != "StrongP@ssw0rd2026!"


def test_user_password_length_validation(app):
    """Verify password shorter than 8 characters is rejected."""
    with app.app_context():
        user = User(username="tester", email="test@appsentinel.io")
        with pytest.raises(ValueError, match="at least 8 characters"):
            user.set_password("short")


def test_target_creation_and_domain_parsing(app):
    """Verify Target model parses domain and generates verification token."""
    with app.app_context():
        user = User(username="analyst_1", email="a1@appsentinel.io")
        user.set_password("ValidPassword123!")
        db.session.add(user)
        db.session.commit()

        target = Target(
            name="Staging API",
            target_url="https://api.staging.example.com:8443/v1/auth",
            owner_id=user.id,
        )
        db.session.add(target)
        db.session.commit()

        assert target.domain == "api.staging.example.com"
        assert len(target.verification_token) == 64
        assert target.is_verified is False


def test_scan_and_vulnerability_relationships(app):
    """Verify cascading relations between Scan, Vulnerability, and Evidence."""
    with app.app_context():
        user = User(username="auditor", email="auditor@appsentinel.io")
        user.set_password("AuditorSecure2026!")
        db.session.add(user)
        db.session.commit()

        target = Target(name="Test Site", target_url="https://example.com", owner_id=user.id)
        db.session.add(target)
        db.session.commit()

        scan = Scan(target_id=target.id, user_id=user.id, scan_type="full", status="completed")
        db.session.add(scan)
        db.session.commit()

        vuln = Vulnerability(
            scan_id=scan.id,
            title="SQL Injection in user parameter",
            vulnerability_type="sqli",
            severity="Critical",
            cvss_score=9.8,
            owasp_category="A03:2021-Injection",
            affected_url="https://example.com/api/users",
            parameter="id",
            description="Time-based blind SQL injection detected.",
        )
        db.session.add(vuln)
        db.session.commit()

        evidence = VulnerabilityEvidence(
            vulnerability_id=vuln.id,
            payload="' OR SLEEP(5)--",
            evidence_snippet="Response latency 5012ms vs baseline 48ms",
        )
        db.session.add(evidence)

        ai = AIAnalysis(
            vulnerability_id=vuln.id,
            explanation="Untrusted user input interpolated directly into SQL statement.",
            potential_impact="Full database exfiltration and arbitrary data tampering.",
            root_cause="Lack of prepared statements with parameterized queries.",
            recommended_remediation="Rewrite dynamic query using SQLAlchemy parameterized statements.",
            is_fallback=True,
        )
        db.session.add(ai)

        report = Report(
            scan_id=scan.id,
            user_id=user.id,
            title="AppSentinel Security Audit - example.com",
            file_path="reports/scan_1_audit.pdf",
            file_format="PDF",
        )
        db.session.add(report)
        db.session.commit()

        # Query and assert relations
        loaded_scan = db.session.get(Scan, scan.id)
        assert loaded_scan.vulnerabilities.count() == 1
        loaded_vuln = loaded_scan.vulnerabilities.first()
        assert loaded_vuln.severity == "Critical"
        assert loaded_vuln.evidences.count() == 1
        assert loaded_vuln.ai_analysis is not None
        assert loaded_vuln.ai_analysis.is_fallback is True
        assert loaded_scan.reports.count() == 1
