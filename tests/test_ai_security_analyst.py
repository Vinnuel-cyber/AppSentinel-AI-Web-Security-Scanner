"""AppSentinel Security Analyst Orchestration Tests (V8)."""

import json
from unittest.mock import MagicMock
import pytest
from app.models import db, User, Target, Scan, Vulnerability
from app.models.vulnerability import AIAnalysis
from app.models.ai import AIConversation, AIMessage, AIUsageLog
from app.ai.security_analyst import SecurityAnalyst


@pytest.fixture
def analyst_test_data(app):
    """Fixture providing user, target, and vulnerability records for analyst tests."""
    with app.app_context():
        user = User(username="analyst_user", email="analyst@test.local", role="USER")
        user.set_password("SecurePassword123!")
        db.session.add(user)
        db.session.commit()

        target = Target(
            name="Bank Portal",
            target_url="https://bank.test",
            domain="bank.test",
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
            title="SQL Injection in Transfer API",
            vulnerability_type="sqli",
            severity="CRITICAL",
            confidence="CONFIRMED",
            cvss_score=9.8,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            owasp_category="A03:2025-Injection",
            cwe_id="CWE-89",
            affected_url="https://bank.test/api/transfer",
            parameter="account_id",
            description="SQL query concatenation allows arbitrary SQL execution.",
        )
        db.session.add(vuln)
        db.session.commit()

        return user.id, target.id, vuln.id


def test_analyze_vulnerability_fallback(client, analyst_test_data):
    """Verify SecurityAnalyst generates deterministic fallback analysis and persists record."""
    user_id, target_id, vuln_id = analyst_test_data
    with client.application.app_context():
        analyst = SecurityAnalyst()
        success, result, analysis_rec, msg = analyst.analyze_vulnerability(
            finding_id=vuln_id,
            user_id=user_id,
        )

        assert success is True
        assert analysis_rec is not None
        assert analysis_rec.vulnerability_id == vuln_id
        assert analysis_rec.is_fallback is True
        assert analysis_rec.status == "COMPLETED"
        assert "SQL" in analysis_rec.root_cause or "parameter" in analysis_rec.root_cause.lower()

        # Check DB persistence
        persisted = AIAnalysis.query.filter_by(vulnerability_id=vuln_id).first()
        assert persisted is not None
        assert persisted.id == analysis_rec.id

        # Verify usage log
        log = AIUsageLog.query.filter_by(user_id=user_id).first()
        assert log is not None
        assert log.analysis_type == "vulnerability_explanation"


def test_analyze_vulnerability_caching(client, analyst_test_data):
    """Verify existing analysis is returned from cache on subsequent calls."""
    user_id, target_id, vuln_id = analyst_test_data
    with client.application.app_context():
        analyst = SecurityAnalyst()
        # First call creates record
        analyst.analyze_vulnerability(finding_id=vuln_id, user_id=user_id)

        # Second call should load from cache
        success, result, analysis_rec, msg = analyst.analyze_vulnerability(
            finding_id=vuln_id,
            user_id=user_id,
            force_refresh=False,
        )
        assert success is True
        assert "Loaded from analysis cache" in msg


def test_analyze_target_posture(client, analyst_test_data):
    """Verify target posture evaluation generates expected summary."""
    user_id, target_id, vuln_id = analyst_test_data
    with client.application.app_context():
        analyst = SecurityAnalyst()
        success, result, msg = analyst.analyze_target(target_id=target_id, user_id=user_id)

        assert success is True
        assert result["analysis_type"] == "target_summary"
        assert "Bank Portal" in result["summary"]


def test_process_chat_query_grounding(client, analyst_test_data):
    """Verify security chat creates conversation and assistant message grounded in DB context."""
    user_id, target_id, vuln_id = analyst_test_data
    with client.application.app_context():
        analyst = SecurityAnalyst()
        success, result, conv, asst_msg, msg = analyst.process_chat_query(
            user_id=user_id,
            user_query="What vulnerabilities were found on Bank Portal?",
            target_id=target_id,
        )

        assert success is True
        assert conv is not None
        assert asst_msg is not None
        assert asst_msg.role == "assistant"
        assert conv.messages.count() == 2  # user + assistant

        # Check in DB
        db_conv = db.session.get(AIConversation, conv.id)
        assert db_conv is not None
        assert db_conv.user_id == user_id


def test_daily_rate_limiting(client, analyst_test_data, monkeypatch):
    """Verify user request is blocked when daily rate limit is exceeded."""
    user_id, target_id, vuln_id = analyst_test_data
    monkeypatch.setenv("AI_DAILY_LIMIT_PER_USER", "2")

    with client.application.app_context():
        analyst = SecurityAnalyst()
        # Log 2 fake requests today
        for _ in range(2):
            SecurityAnalyst.log_usage(
                user_id=user_id,
                provider="test",
                model="test",
                analysis_type="vulnerability_explanation",
                input_tokens=0,
                output_tokens=0,
                status="SUCCESS",
            )

        allowed, count, limit = SecurityAnalyst.check_daily_limit(user_id)
        assert allowed is False

        # Attempting analysis should fail
        success, res, rec, msg = analyst.analyze_vulnerability(finding_id=vuln_id, user_id=user_id, force_refresh=True)
        assert success is False
        assert "limit reached" in msg.lower()


def test_admin_daily_rate_limit_exemption(client, analyst_test_data):
    """Verify administrator requests bypass daily rate limit throttling."""
    user_id, target_id, vuln_id = analyst_test_data
    with client.application.app_context():
        allowed, count, limit = SecurityAnalyst.check_daily_limit(user_id, is_admin=True)
        assert allowed is True


def test_usage_log_error_secret_redaction(client, analyst_test_data):
    """Verify secrets in error messages are redacted before database persistence."""
    user_id, _, _ = analyst_test_data
    with client.application.app_context():
        leaked_error = "OpenAI Error: Request failed with key sk-proj-supersecretkey1234567890 and Bearer 1234567890abcdef1234"
        log = SecurityAnalyst.log_usage(
            user_id=user_id,
            provider="openai",
            model="gpt-4o-mini",
            analysis_type="vulnerability_explanation",
            input_tokens=0,
            output_tokens=0,
            status="FALLBACK",
            error_message=leaked_error,
        )
        assert "sk-proj-supersecret" not in log.error_message
        assert "[REDACTED_API_KEY]" in log.error_message
        assert "Bearer [REDACTED_TOKEN]" in log.error_message
