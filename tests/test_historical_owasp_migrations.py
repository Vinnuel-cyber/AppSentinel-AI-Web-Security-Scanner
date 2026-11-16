import pytest
from app.models import (
    db,
    User,
    Target,
    Scan,
    Vulnerability,
    OWASPAssessment,
    OWASPFindingMapping,
    RiskAssessment,
)
from app.services.owasp_service import OWASPService
from app.models.migrations import run_database_migrations


def test_mixed_version_assessment_history_and_migrations(app):
    """Verify historical 2021 assessments coexist with 2025 assessments without mutation."""
    with app.app_context():
        # Run idempotent migrations
        run_database_migrations(app)

        # 1. Create User and Target
        user = User(username="migration_test_user", email="migration@test.local", role="USER")
        user.set_password("SecurePass123!")
        db.session.add(user)
        db.session.commit()

        target = Target(
            name="Migration Target",
            target_url="https://migration.test.local",
            domain="migration.test.local",
            owner_id=user.id,
            is_verified=True,
            verification_status="VERIFIED",
            verification_method="dns_txt",
            environment="Production",
        )
        db.session.add(target)
        db.session.commit()

        scan = Scan(target_id=target.id, user_id=user.id, status="completed")
        db.session.add(scan)
        db.session.commit()

        # Add sample vulnerability
        vuln = Vulnerability(
            scan_id=scan.id,
            target_id=target.id,
            title="SQL Injection (SQLite Error-Based)",
            vulnerability_type="Injection",
            owasp_category="A03:2021 - Injection",
            severity="CRITICAL",
            confidence="CONFIRMED",
            scanner_module="sqli_scanner",
            affected_url="https://migration.test.local/login",
            description="SQL injection in login parameter",
            cwe_id="CWE-89",
        )
        db.session.add(vuln)
        db.session.commit()

        # 2. Simulate historical 2021 assessment
        assessment_2021 = OWASPService.run_target_assessment(
            target_id=target.id,
            user_id=user.id,
            framework_version="2021",
        )
        assert assessment_2021.framework_version == "2021"
        assert "A03:2021" in assessment_2021.get_summary()["category_distribution"]
        historical_id = assessment_2021.id

        # 3. Simulate newer 2025 assessment on the same target
        assessment_2025 = OWASPService.run_target_assessment(
            target_id=target.id,
            user_id=user.id,
            framework_version="2025",
        )
        assert assessment_2025.framework_version == "2025"
        assert "A05:2025" in assessment_2025.get_summary()["category_distribution"]
        new_id = assessment_2025.id

        # 4. Assert historical assessment was NOT mutated or converted
        persisted_2021 = db.session.get(OWASPAssessment, historical_id)
        assert persisted_2021.framework_version == "2021"
        assert "A03:2021" in persisted_2021.get_summary()["category_distribution"]
        assert "A05:2025" not in persisted_2021.get_summary()["category_distribution"]

        # 5. Assert 2025 assessment is separate
        persisted_2025 = db.session.get(OWASPAssessment, new_id)
        assert persisted_2025.framework_version == "2025"
        assert "A05:2025" in persisted_2025.get_summary()["category_distribution"]

        # 6. Verify Foreign Key relationships and ownership
        assert persisted_2021.target_id == target.id
        assert persisted_2025.target_id == target.id
        assert target.owasp_assessments.count() == 2

        # 7. Check RiskAssessment integrity
        risk = RiskAssessment.query.filter_by(vulnerability_id=vuln.id).first()
        assert risk is not None
        assert risk.cvss_version == "4.0"
        assert risk.cvss_score == 9.3
        assert risk.severity_rating == "Critical"
        assert risk.target_id == target.id
