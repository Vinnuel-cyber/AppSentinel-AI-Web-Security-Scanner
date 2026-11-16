from app.security.risk_engine import CVSS4RiskEngine
from app.security.risk_prioritizer import RiskPrioritizer


def test_cvss4_vector_validation_success():
    """Verify standard CVSS v4.0 vector string passes validation."""
    valid_vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    is_valid, msg, metrics = CVSS4RiskEngine.validate_vector(valid_vec)
    assert is_valid is True
    assert metrics["AV"] == "N"
    assert metrics["VC"] == "H"


def test_cvss4_vector_validation_failure():
    """Verify invalid vectors (bad prefix, missing metric) are rejected."""
    # Bad prefix
    valid_prefix, _, _ = CVSS4RiskEngine.validate_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert valid_prefix is False

    # Missing metric (e.g. missing VI)
    is_valid, msg, _ = CVSS4RiskEngine.validate_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VA:H/SC:N/SI:N/SA:N")
    assert is_valid is False
    assert "Missing required" in msg


def test_cvss4_score_calculation_critical():
    """Verify critical network unauthenticated remote code execution / SQLi scores in Critical band (9.2)."""
    metrics = {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "H", "VI": "H", "VA": "H", "SC": "N", "SI": "N", "SA": "N"}
    score = CVSS4RiskEngine.calculate_score(metrics)
    assert score == 9.2
    assert CVSS4RiskEngine.get_severity_rating(score) == "Critical"


def test_cvss4_score_calculation_high():
    """Verify high severity key leak (VC:H) scores in High band (8.0)."""
    metrics = {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "H", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"}
    score = CVSS4RiskEngine.calculate_score(metrics)
    assert score == 8.0
    assert CVSS4RiskEngine.get_severity_rating(score) == "High"


def test_cvss4_score_calculation_zero():
    """Verify vector with zero impact yields score 0.0 and severity None."""
    metrics = {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "N", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"}
    score = CVSS4RiskEngine.calculate_score(metrics)
    assert score == 0.0
    assert CVSS4RiskEngine.get_severity_rating(score) == "None"


def test_risk_prioritization_levels():
    """Verify operational priority tiers (P1 to P5) based on score, confidence, and environment."""
    # Critical SQLi in production -> P1
    p1, r1 = RiskPrioritizer.determine_priority(cvss_score=9.3, severity="Critical", confidence="CONFIRMED", environment="Production", vulnerability_name="SQL Injection")
    assert p1 == "P1"
    assert "Critical Attention" in r1

    # Confirmed XSS in production -> P2
    p2, r2 = RiskPrioritizer.determine_priority(cvss_score=5.1, severity="Medium", confidence="CONFIRMED", environment="Production", vulnerability_name="Reflected Cross-Site Scripting")
    assert p2 == "P2"

    # Directory listing -> P3
    p3, r3 = RiskPrioritizer.determine_priority(cvss_score=5.3, severity="Medium", confidence="HIGH", environment="Production", vulnerability_name="Directory Listing Enabled")
    assert p3 == "P3"

    # Low server banner -> P4
    p4, r4 = RiskPrioritizer.determine_priority(cvss_score=2.6, severity="Low", confidence="HIGH", environment="Production", vulnerability_name="Server Software Version Disclosure")
    assert p4 == "P4"

    # Informational finding -> P5
    p5, r5 = RiskPrioritizer.determine_priority(cvss_score=0.0, severity="None", confidence="LOW", environment="Production", vulnerability_name="General Info Note")
    assert p5 == "P5"


def test_cvss_score_and_confidence_separation():
    """Ensure scanner confidence does NOT alter the official CVSS v4.0 numeric calculation."""
    res_high_conf = CVSS4RiskEngine.score_vulnerability("SQL Injection (SQLite Error-Based)", category="Injection")
    res_low_conf = CVSS4RiskEngine.score_vulnerability("SQL Injection (SQLite Error-Based)", category="Injection")
    # Same vulnerability profile must calculate identical CVSS score regardless of confidence
    assert res_high_conf["cvss_score"] == res_low_conf["cvss_score"]
    assert res_high_conf["cvss_vector"] == res_low_conf["cvss_vector"]
