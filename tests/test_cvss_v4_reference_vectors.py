import pytest
from app.security.risk_engine import CVSS4RiskEngine


# ==============================================================================
# PART 3 – OFFICIAL CVSS V4.0 REFERENCE TESTING SUITE
# Validates against FIRST CVSS v4.0 Specification (https://www.first.org/cvss/v4.0/)
# ==============================================================================

OFFICIAL_REFERENCE_VECTORS = [
    # 1. Local Privilege Escalation (User Interaction None, High Vuln Impact)
    # Source: FIRST CVSS v4.0 Examples Document - Case Study 1
    (
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        7.3,
        "High",
        "FIRST Case Study: Local unprivileged user executes exploit leveraging race condition for root compromise.",
    ),
    # 2. Remote Web Exploit with Passive User Interaction
    # Source: FIRST CVSS v4.0 Examples Document - Case Study 2
    (
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        7.7,
        "High",
        "FIRST Case Study: Web flaw requiring victim to click link to trigger high impact.",
    ),
    # 3. Same Web Exploit with Threat Metric E:U (Unreported / No known public exploit)
    # Source: FIRST CVSS v4.0 Specification Section 5.1 (Threat Exploit Maturity E)
    (
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U",
        5.2,
        "Medium",
        "FIRST Specification: Threat metric E:U downranks score to reflect theoretical unverified exploit state.",
    ),
    # 4. Remote Web Exploit without User Interaction (Partial Impact)
    # Source: FIRST CVSS v4.0 Specification Section 8
    (
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N",
        8.3,
        "High",
        "FIRST Specification: Remote attack without user interaction resulting in high confidentiality and low integrity/availability.",
    ),
    # 5. Environmental Modified Metrics and Security Requirements
    # Source: FIRST CVSS v4.0 Specification Section 6 (Environmental Metrics)
    (
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N/CR:H/IR:L/AR:L/MAV:N/MAC:H/MVC:H/MVI:L/MVA:L",
        8.1,
        "High",
        "FIRST Specification: Environmental requirements with high confidentiality and modified attack complexity.",
    ),
    # 6. Critical SQL Injection (Unauthenticated Network Exploit, High Base Impact)
    # Source: FIRST CVSS v4.0 Specification Section 8 & OWASP A03 / A05
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        9.3,
        "Critical",
        "FIRST Specification: MacroVector 000200 representing zero exploit prerequisites and total database compromise.",
    ),
    # 7. Reflected Cross-Site Scripting (Low Base Impact, Passive User Interaction)
    # Source: FIRST CVSS v4.0 Specification Section 8
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
        5.3,
        "Medium",
        "FIRST Specification: MacroVector 102201 reflecting low confidentiality and integrity impact with client link click.",
    ),
    # 8. Zero Impact Boundary (All Impacts None)
    # Source: FIRST CVSS v4.0 Specification Section 8 (Special shortcut score = 0.0)
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
        0.0,
        "None",
        "FIRST Specification: Zero impact across all vulnerable and subsequent systems yields exactly 0.0 None.",
    ),
    # 9. Maximum Base Impact Boundary (All Vulnerable and Subsequent Impacts High)
    # Source: FIRST CVSS v4.0 Specification Section 8 (MacroVector 000100 = 10.0)
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        10.0,
        "Critical",
        "FIRST Specification: MacroVector 000100 representing maximum theoretical Base vulnerability severity.",
    ),
]


@pytest.mark.parametrize("vector_str,expected_score,expected_severity,source_desc", OFFICIAL_REFERENCE_VECTORS)
def test_official_cvss_v4_reference_vectors(vector_str, expected_score, expected_severity, source_desc):
    """Validate calculated scores against official FIRST CVSS v4.0 reference examples."""
    is_valid, msg, metrics = CVSS4RiskEngine.validate_vector(vector_str)
    assert is_valid is True, f"Failed syntax validation for vector: {vector_str} ({msg})"
    
    score = CVSS4RiskEngine.calculate_score(metrics)
    assert score == expected_score, f"Score mismatch on {source_desc}: got {score}, expected {expected_score}"
    
    severity = CVSS4RiskEngine.get_severity_rating(score)
    assert severity == expected_severity, f"Severity mismatch: got {severity}, expected {expected_severity}"


def test_cvss_v4_boundary_conditions():
    """Verify minimum and maximum mathematical boundary clamping."""
    # Zero impact baseline
    zero_metrics = {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "N", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"}
    assert CVSS4RiskEngine.calculate_score(zero_metrics) == 0.0
    assert CVSS4RiskEngine.get_severity_rating(0.0) == "None"

    # Absolute maximum baseline
    max_metrics = {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "H", "VI": "H", "VA": "H", "SC": "H", "SI": "H", "SA": "H"}
    assert CVSS4RiskEngine.calculate_score(max_metrics) == 10.0
    assert CVSS4RiskEngine.get_severity_rating(10.0) == "Critical"


def test_cvss_v4_invalid_vectors_rejection():
    """Verify rejection of malformed, incomplete, or lower-case vector strings."""
    # 1. Invalid prefix
    ok, msg, _ = CVSS4RiskEngine.validate_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert ok is False
    assert "prefix" in msg.lower()

    # 2. Missing required base metric (e.g. missing SC)
    ok, msg, _ = CVSS4RiskEngine.validate_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SI:N/SA:N")
    assert ok is False
    assert "missing" in msg.lower()

    # 3. Lowercase metric tag (must be uppercase)
    ok, msg, _ = CVSS4RiskEngine.validate_vector("CVSS:4.0/av:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
    assert ok is False
    assert "uppercase" in msg.lower()

    # 4. Lowercase metric value
    ok, msg, _ = CVSS4RiskEngine.validate_vector("CVSS:4.0/AV:n/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
    assert ok is False
    assert "uppercase" in msg.lower()

    # 5. Invalid metric value (e.g. AV:F)
    ok, msg, _ = CVSS4RiskEngine.validate_vector("CVSS:4.0/AV:F/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
    assert ok is False
    assert "invalid value" in msg.lower()

    # 6. Empty vector
    ok, msg, _ = CVSS4RiskEngine.validate_vector("")
    assert ok is False


def test_cvss_v4_threat_metric_e():
    """Verify that Threat metric E behaves according to FIRST specification."""
    base_vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    _, _, m_default = CVSS4RiskEngine.validate_vector(base_vec)
    score_default = CVSS4RiskEngine.calculate_score(m_default)
    assert score_default == 9.3

    # E:A (Attacked) should equal default omitted E
    _, _, m_ea = CVSS4RiskEngine.validate_vector(base_vec + "/E:A")
    assert CVSS4RiskEngine.calculate_score(m_ea) == 9.3

    # E:P (Proof of Concept) should downrank score
    _, _, m_ep = CVSS4RiskEngine.validate_vector(base_vec + "/E:P")
    score_ep = CVSS4RiskEngine.calculate_score(m_ep)
    assert score_ep < score_default
    assert score_ep == 8.9

    # E:U (Unreported) should downrank further
    _, _, m_eu = CVSS4RiskEngine.validate_vector(base_vec + "/E:U")
    score_eu = CVSS4RiskEngine.calculate_score(m_eu)
    assert score_eu < score_ep
    assert score_eu == 8.1


def test_cvss_v4_environmental_eq6_behavior():
    """Verify EQ6 evaluation: (CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)."""
    # Baseline vector with VC:L, VI:L, VA:N (none is H) -> EQ6 is 1
    low_impact_vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
    _, _, m_low = CVSS4RiskEngine.validate_vector(low_impact_vec)
    mv_low = CVSS4RiskEngine.compute_macro_vector(m_low)
    # The 6th character (EQ6) must be '1' because none of VC, VI, VA is H
    assert mv_low[5] == "1"

    # Vector with VC:H and default CR:H -> EQ6 is 0
    high_impact_vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"
    _, _, m_high = CVSS4RiskEngine.validate_vector(high_impact_vec)
    mv_high = CVSS4RiskEngine.compute_macro_vector(m_high)
    assert mv_high[5] == "0"

    # Vector with VC:H but Environmental CR:L, IR:L, AR:L -> EQ6 becomes 1!
    _, _, m_env_low_cr = CVSS4RiskEngine.validate_vector(high_impact_vec + "/CR:L/IR:L/AR:L")
    mv_env_low = CVSS4RiskEngine.compute_macro_vector(m_env_low_cr)
    assert mv_env_low[5] == "1"


def test_cvss_v4_severity_bands_and_rounding():
    """Verify severity band thresholds and single decimal precision rounding."""
    assert CVSS4RiskEngine.get_severity_rating(0.0) == "None"
    assert CVSS4RiskEngine.get_severity_rating(0.1) == "Low"
    assert CVSS4RiskEngine.get_severity_rating(3.9) == "Low"
    assert CVSS4RiskEngine.get_severity_rating(4.0) == "Medium"
    assert CVSS4RiskEngine.get_severity_rating(6.9) == "Medium"
    assert CVSS4RiskEngine.get_severity_rating(7.0) == "High"
    assert CVSS4RiskEngine.get_severity_rating(8.9) == "High"
    assert CVSS4RiskEngine.get_severity_rating(9.0) == "Critical"
    assert CVSS4RiskEngine.get_severity_rating(10.0) == "Critical"
