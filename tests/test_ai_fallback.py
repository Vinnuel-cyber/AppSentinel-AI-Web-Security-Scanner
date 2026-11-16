"""AppSentinel Deterministic Fallback Engine Tests (V8)."""

from app.ai.fallback_engine import FallbackEngine
from app.ai.response_validator import ResponseValidator


def test_fallback_sqli_explanation():
    """Verify offline deterministic analysis for SQL Injection."""
    finding = {
        "title": "SQL Injection in User Authentication",
        "category": "sqli",
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
        "cvss_score": 9.8,
        "affected_url": "https://example.com/api/login",
        "parameter": "username",
        "evidence": "Observed syntax error on quote probe",
    }
    result = FallbackEngine.generate_vulnerability_analysis(finding)

    assert result["analysis_type"] == "vulnerability_explanation"
    assert "SQL" in result["summary"]
    assert "parameterized" in result["root_cause"].lower() or "concatenation" in result["root_cause"].lower()
    assert len(result["recommendations"]) >= 1
    assert "SQLAlchemy" in result["recommendations"][0]["code_example"]
    assert len(result["verification_steps"]) >= 1
    assert result["ai_confidence"] in ["HIGH", "MEDIUM"]


def test_fallback_xss_explanation():
    """Verify offline deterministic analysis for Reflected XSS."""
    finding = {
        "title": "Reflected Cross-Site Scripting",
        "category": "xss",
        "severity": "HIGH",
        "confidence": "CONFIRMED",
        "cvss_score": 7.5,
        "affected_url": "https://example.com/search?q=test",
        "parameter": "q",
    }
    result = FallbackEngine.generate_vulnerability_analysis(finding)

    assert "XSS" in result["summary"] or "Cross-Site Scripting" in result["summary"]
    assert "JavaScript" in result["impact"]
    assert any("Content-Security-Policy" in r.get("code_example", "") or "Jinja2" in r.get("code_example", "") for r in result["recommendations"])


def test_fallback_cookie_security():
    """Verify offline deterministic analysis for insecure session cookies."""
    finding = {
        "title": "Cookie Missing HttpOnly Flag",
        "category": "cookie",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "cvss_score": 5.3,
        "affected_url": "https://example.com/",
    }
    result = FallbackEngine.generate_vulnerability_analysis(finding)

    assert "Cookie" in result["summary"] or "session" in result["summary"].lower()
    assert "SESSION_COOKIE_HTTPONLY" in result["recommendations"][0]["code_example"]


def test_fallback_target_summary():
    """Verify offline deterministic target posture assessment."""
    target_data = {
        "name": "Portal App",
        "target_url": "https://portal.test",
        "environment": "Staging",
        "findings_summary": {
            "total": 3,
            "critical": 1,
            "high": 1,
            "medium": 1,
            "low": 0,
            "avg_cvss": 7.4,
        },
        "top_findings": [
            {"title": "SQLi", "severity": "CRITICAL", "cvss_score": 9.8, "affected_url": "https://portal.test/login"},
            {"title": "XSS", "severity": "HIGH", "cvss_score": 7.5, "affected_url": "https://portal.test/search"},
        ],
    }
    summary = FallbackEngine.generate_target_summary(target_data)

    assert summary["analysis_type"] == "target_summary"
    assert "Portal App" in summary["summary"]
    assert "3 total findings" in summary["summary"]
    assert len(summary["recommendations"]) >= 1


def test_fallback_chat_responses():
    """Verify offline chat response answers security questions without external network."""
    resp1 = FallbackEngine.generate_chat_response("How do I prevent SQL injection in Flask?")
    assert "SQL" in resp1["summary"] or "parameter" in resp1["technical_explanation"].lower()

    resp2 = FallbackEngine.generate_chat_response("Explain XSS mitigation and CSP")
    assert "XSS" in resp2["summary"] or "Content-Security-Policy" in resp2["technical_explanation"]

    resp3 = FallbackEngine.generate_chat_response("Tell me about OWASP 2025")
    assert "OWASP" in resp3["summary"]
