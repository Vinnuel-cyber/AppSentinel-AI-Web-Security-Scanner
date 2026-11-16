"""Official FIRST CVSS v4.0 Compliance Audit and Validation Test Suite.

Validates AppSentinel's CVSS v4.0 Risk Engine (app/security/risk_engine.py)
against the official FIRST CVSS v4.0 specification:
https://www.first.org/cvss/v4.0/specification-document
and reference datasets:
https://github.com/FIRSTdotorg/cvss-resources

Audit Areas Covered:
1. Base metric SI and SA accept ONLY their valid Base values {H, L, N} and reject 'S'.
2. Modified metrics MSI and MSA accept the additional Safety value 'S' {X, S, H, L, N}.
3. Supplemental Safety 'S' is treated as a separate metric {X, N, P} and does not mutate score.
4. Additional Supplemental metrics (AU, R, V, RE, U) validate correctly and do not alter score.
5. "Not Defined" (X) handling preserves 'X' in vectors and evaluates correctly in scoring:
   - E:X evaluates equivalent to E:A
   - CR:X, IR:X, AR:X evaluate equivalent to H
   - M*:X evaluates using corresponding Base metric
6. Vector validation: rejects duplicates, unknown metric tags, lowercase syntax, invalid values.
7. Accurate score nomenclature: CVSS-B, CVSS-BT, CVSS-BE, CVSS-BTE.
8. Canonical vector serialization and ordering.
9. Equivalence sets coverage across EQ1 through EQ6.
"""

import pytest
from app.security.risk_engine import CVSS4RiskEngine


# ==============================================================================
# 1. BASE SI & SA METRICS: REJECTION OF 'S' (SAFETY)
# In FIRST CVSS v4.0: Base SI and SA can only be H, L, N. 'S' is NOT a Base value.
# ==============================================================================

def test_base_si_rejects_safety_value():
    """Ensure Base SI rejects 'S' (Safety is only valid for Modified MSI or Supplemental S)."""
    # Attempt Base SI:S
    vec_si_s = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:S/SA:N"
    ok, msg, _ = CVSS4RiskEngine.validate_vector(vec_si_s)
    assert ok is False, "Base SI:S must be rejected per FIRST CVSS v4.0 specification"
    assert "invalid value" in msg.lower() and "si" in msg.lower()


def test_base_sa_rejects_safety_value():
    """Ensure Base SA rejects 'S' (Safety is only valid for Modified MSA or Supplemental S)."""
    # Attempt Base SA:S
    vec_sa_s = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:S"
    ok, msg, _ = CVSS4RiskEngine.validate_vector(vec_sa_s)
    assert ok is False, "Base SA:S must be rejected per FIRST CVSS v4.0 specification"
    assert "invalid value" in msg.lower() and "sa" in msg.lower()


def test_base_si_and_sa_accept_valid_values():
    """Verify Base SI and SA accept valid values H, L, N."""
    for val in ["H", "L", "N"]:
        vec = f"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:{val}/SA:{val}"
        ok, msg, metrics = CVSS4RiskEngine.validate_vector(vec)
        assert ok is True, f"Base SI:{val}/SA:{val} must be accepted: {msg}"
        assert metrics["SI"] == val
        assert metrics["SA"] == val


# ==============================================================================
# 2. MODIFIED MSI & MSA METRICS: ACCEPTANCE OF 'S' (SAFETY) & EQ4 LEVEL 0
# ==============================================================================

def test_modified_msi_accepts_safety_value_and_triggers_eq4_level_0():
    """Verify Modified MSI accepts 'S' and triggers MacroVector EQ4 Level 0."""
    vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MSI:S"
    ok, msg, metrics = CVSS4RiskEngine.validate_vector(vec)
    assert ok is True, f"MSI:S must be accepted as valid: {msg}"
    assert metrics["MSI"] == "S"

    # MacroVector EQ4 (4th digit, index 3) must be '0'
    mv = CVSS4RiskEngine.compute_macro_vector(metrics)
    assert mv[3] == "0", f"EQ4 must be '0' when MSI:S is present, got {mv}"

    # Score calculation
    score = CVSS4RiskEngine.calculate_score(metrics)
    assert score == 10.0, f"Expected 10.0 for MacroVector 000000, got {score}"


def test_modified_msa_accepts_safety_value_and_triggers_eq4_level_0():
    """Verify Modified MSA accepts 'S' and triggers MacroVector EQ4 Level 0."""
    vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MSA:S"
    ok, msg, metrics = CVSS4RiskEngine.validate_vector(vec)
    assert ok is True, f"MSA:S must be accepted as valid: {msg}"
    assert metrics["MSA"] == "S"

    mv = CVSS4RiskEngine.compute_macro_vector(metrics)
    assert mv[3] == "0", f"EQ4 must be '0' when MSA:S is present, got {mv}"

    score = CVSS4RiskEngine.calculate_score(metrics)
    assert score == 10.0


def test_modified_msi_and_msa_all_valid_values():
    """Verify MSI and MSA accept {X, S, H, L, N}."""
    for val in ["X", "S", "H", "L", "N"]:
        vec = f"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MSI:{val}/MSA:{val}"
        ok, msg, metrics = CVSS4RiskEngine.validate_vector(vec)
        assert ok is True, f"MSI:{val}/MSA:{val} must be accepted: {msg}"
        assert metrics["MSI"] == val
        assert metrics["MSA"] == val


# ==============================================================================
# 3. SUPPLEMENTAL SAFETY METRIC (S) SEPARATION & NON-INTERFERENCE
# In FIRST CVSS v4.0: Supplemental Safety S accepts {X, N, P}. Does not affect score.
# ==============================================================================

def test_supplemental_safety_metric_values():
    """Verify Supplemental Safety S accepts {X, N, P} and rejects 'S' or invalid values."""
    base_vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

    # S:P (Present)
    ok, msg, m_sp = CVSS4RiskEngine.validate_vector(base_vec + "/S:P")
    assert ok is True
    assert m_sp["S"] == "P"

    # S:N (Negligible)
    ok, msg, m_sn = CVSS4RiskEngine.validate_vector(base_vec + "/S:N")
    assert ok is True
    assert m_sn["S"] == "N"

    # S:X (Not Defined)
    ok, msg, m_sx = CVSS4RiskEngine.validate_vector(base_vec + "/S:X")
    assert ok is True
    assert m_sx["S"] == "X"

    # S:S must be REJECTED (Safety metric values are N or P, not S!)
    ok, msg, _ = CVSS4RiskEngine.validate_vector(base_vec + "/S:S")
    assert ok is False, "Supplemental Safety S:S must be rejected"


def test_supplemental_safety_does_not_mutate_score_or_macrovector():
    """Verify Supplemental Safety does NOT alter score or MacroVector (only MSI/MSA does)."""
    base_vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    _, _, m_base = CVSS4RiskEngine.validate_vector(base_vec)
    score_base = CVSS4RiskEngine.calculate_score(m_base)
    mv_base = CVSS4RiskEngine.compute_macro_vector(m_base)

    # Adding Supplemental S:P
    _, _, m_sp = CVSS4RiskEngine.validate_vector(base_vec + "/S:P")
    score_sp = CVSS4RiskEngine.calculate_score(m_sp)
    mv_sp = CVSS4RiskEngine.compute_macro_vector(m_sp)

    # Base score is 9.3 (MacroVector 000200)
    assert score_base == 9.3
    assert mv_base == "000200"
    # Supplemental S:P must NOT change score or macrovector
    assert score_sp == score_base
    assert mv_sp == mv_base


# ==============================================================================
# 4. COMPREHENSIVE SUPPLEMENTAL METRICS AUDIT (AU, R, V, RE, U)
# ==============================================================================

def test_all_supplemental_metrics_validation():
    """Verify all FIRST CVSS v4.0 Supplemental metrics validate correctly."""
    base_vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    full_supp_vec = base_vec + "/S:P/AU:Y/R:A/V:C/RE:L/U:Clear"

    ok, msg, metrics = CVSS4RiskEngine.validate_vector(full_supp_vec)
    assert ok is True, f"Full supplemental vector failed validation: {msg}"
    assert metrics["S"] == "P"
    assert metrics["AU"] == "Y"
    assert metrics["R"] == "A"
    assert metrics["V"] == "C"
    assert metrics["RE"] == "L"
    assert metrics["U"] == "Clear"

    # Score must remain identical to base vector
    score = CVSS4RiskEngine.calculate_score(metrics)
    assert score == 9.3


def test_provider_urgency_valid_values():
    """Verify Provider Urgency (U) accepts exactly official case-sensitive values: X, Clear, Green, Amber, Red."""
    base_vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    for urgency in ["X", "Clear", "Green", "Amber", "Red"]:
        vec = f"{base_vec}/U:{urgency}"
        ok, msg, metrics = CVSS4RiskEngine.validate_vector(vec)
        assert ok is True, f"Provider Urgency U:{urgency} failed: {msg}"
        assert metrics["U"] == urgency


def test_provider_urgency_rejects_invalid_case_and_values():
    """Verify Provider Urgency (U) strictly rejects uppercase, lowercase, and invalid strings."""
    base_vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

    # Uppercase variations must be rejected per FIRST CVSS v4.0 specification
    invalid_uppercase = ["CLEAR", "GREEN", "AMBER", "RED"]
    for val in invalid_uppercase:
        vec = f"{base_vec}/U:{val}"
        ok, msg, _ = CVSS4RiskEngine.validate_vector(vec)
        assert ok is False, f"Provider Urgency U:{val} (uppercase) must be rejected"
        assert "invalid value" in msg.lower() and "u" in msg.lower()

    # Lowercase variations must be rejected
    invalid_lowercase = ["clear", "green", "amber", "red", "x"]
    for val in invalid_lowercase:
        vec = f"{base_vec}/U:{val}"
        ok, msg, _ = CVSS4RiskEngine.validate_vector(vec)
        assert ok is False, f"Provider Urgency U:{val} (lowercase) must be rejected"

    # Arbitrary strings must be rejected
    for val in ["High", "Critical", "Moderate", "YELLOW"]:
        vec = f"{base_vec}/U:{val}"
        ok, msg, _ = CVSS4RiskEngine.validate_vector(vec)
        assert ok is False, f"Provider Urgency U:{val} must be rejected"


# ==============================================================================
# 5. "NOT DEFINED" (X) PRESERVATION & SCORING EQUIVALENCE
# ==============================================================================

def test_not_defined_x_preserved_in_vector_string():
    """Ensure 'X' metrics are preserved in vector representations and never silently mutated."""
    vec_with_x = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MSI:X"
    ok, msg, metrics = CVSS4RiskEngine.validate_vector(vec_with_x)
    assert ok is True

    # Vector serialization must preserve X when preserve_x=True
    serialized = CVSS4RiskEngine.build_vector_string(metrics, preserve_x=True)
    assert "E:X" in serialized
    assert "CR:X" in serialized
    assert "IR:X" in serialized
    assert "AR:X" in serialized
    assert "MAV:X" in serialized
    assert "MSI:X" in serialized
    # Must NOT rewrite to E:A or CR:H in stored string
    assert "E:A" not in serialized
    assert "CR:H" not in serialized


def test_threat_e_x_evaluates_equivalent_to_e_a():
    """Scoring behavior: E:X evaluates equivalent to E:A (worst-case Attacked)."""
    base_vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    _, _, m_omitted = CVSS4RiskEngine.validate_vector(base_vec)
    _, _, m_ex = CVSS4RiskEngine.validate_vector(base_vec + "/E:X")
    _, _, m_ea = CVSS4RiskEngine.validate_vector(base_vec + "/E:A")

    score_omitted = CVSS4RiskEngine.calculate_score(m_omitted)
    score_ex = CVSS4RiskEngine.calculate_score(m_ex)
    score_ea = CVSS4RiskEngine.calculate_score(m_ea)

    assert score_ex == score_ea == score_omitted == 9.3


def test_security_requirements_x_evaluates_equivalent_to_high():
    """Scoring behavior: CR:X, IR:X, AR:X evaluate equivalent to H (High requirement)."""
    base_vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    _, _, m_omitted = CVSS4RiskEngine.validate_vector(base_vec)
    _, _, m_x = CVSS4RiskEngine.validate_vector(base_vec + "/CR:X/IR:X/AR:X")
    _, _, m_h = CVSS4RiskEngine.validate_vector(base_vec + "/CR:H/IR:H/AR:H")

    score_omitted = CVSS4RiskEngine.calculate_score(m_omitted)
    score_x = CVSS4RiskEngine.calculate_score(m_x)
    score_h = CVSS4RiskEngine.calculate_score(m_h)

    assert score_x == score_h == score_omitted == 9.3


def test_modified_metrics_x_evaluates_to_corresponding_base_metric():
    """Scoring behavior: M*:X evaluates using the corresponding Base metric."""
    base_vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    mod_x_vec = base_vec + "/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X"

    _, _, m_base = CVSS4RiskEngine.validate_vector(base_vec)
    _, _, m_mod_x = CVSS4RiskEngine.validate_vector(mod_x_vec)

    score_base = CVSS4RiskEngine.calculate_score(m_base)
    score_mod_x = CVSS4RiskEngine.calculate_score(m_mod_x)

    assert score_mod_x == score_base == 9.3
    assert CVSS4RiskEngine.compute_macro_vector(m_mod_x) == CVSS4RiskEngine.compute_macro_vector(m_base)


# ==============================================================================
# 6. VECTOR SYNTAX VALIDATION & ERROR REJECTION
# ==============================================================================

def test_duplicate_metric_rejection():
    """Ensure vectors with duplicate metric tags are rejected."""
    base_vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

    # Duplicate threat metric E
    dup_threat = base_vec + "/E:A/E:P"
    ok, msg, _ = CVSS4RiskEngine.validate_vector(dup_threat)
    assert ok is False
    assert "duplicate" in msg.lower() and "e" in msg.lower()

    # Duplicate base metric AV
    dup_base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/AV:A"
    ok, msg, _ = CVSS4RiskEngine.validate_vector(dup_base)
    assert ok is False
    assert "duplicate" in msg.lower() and "av" in msg.lower()


def test_unknown_metric_rejection():
    """Ensure vectors with unrecognized metric tags are rejected."""
    base_vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    bad_vec = base_vec + "/UNKNOWN:VAL"
    ok, msg, _ = CVSS4RiskEngine.validate_vector(bad_vec)
    assert ok is False
    assert "unknown" in msg.lower() and "unknown" in msg.lower()


def test_base_metrics_cannot_be_not_defined_x():
    """Ensure Base metrics cannot have value 'X' (Base metrics are mandatory)."""
    bad_vec = "CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    ok, msg, _ = CVSS4RiskEngine.validate_vector(bad_vec)
    assert ok is False
    assert "invalid value" in msg.lower() and "av" in msg.lower()


# ==============================================================================
# 7. ACCURATE CVSS SCORE NOMENCLATURE (CVSS-B, CVSS-BT, CVSS-BE, CVSS-BTE)
# ==============================================================================

def test_score_nomenclature_classification():
    """Verify official score nomenclature prefix determination."""
    base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

    # 1. Base only -> CVSS-B
    _, _, m_b = CVSS4RiskEngine.validate_vector(base)
    assert CVSS4RiskEngine.get_score_nomenclature(m_b) == "CVSS-B"

    # Base with E:X (still CVSS-B because E is not defined)
    _, _, m_b_ex = CVSS4RiskEngine.validate_vector(base + "/E:X")
    assert CVSS4RiskEngine.get_score_nomenclature(m_b_ex) == "CVSS-B"

    # Base with Supplemental S:P (still CVSS-B because Supplemental does not alter nomenclature)
    _, _, m_b_sp = CVSS4RiskEngine.validate_vector(base + "/S:P/AU:Y")
    assert CVSS4RiskEngine.get_score_nomenclature(m_b_sp) == "CVSS-B"

    # 2. Base + Threat -> CVSS-BT
    _, _, m_bt = CVSS4RiskEngine.validate_vector(base + "/E:A")
    assert CVSS4RiskEngine.get_score_nomenclature(m_bt) == "CVSS-BT"

    # 3. Base + Environmental -> CVSS-BE
    _, _, m_be_cr = CVSS4RiskEngine.validate_vector(base + "/CR:H")
    assert CVSS4RiskEngine.get_score_nomenclature(m_be_cr) == "CVSS-BE"

    _, _, m_be_mod = CVSS4RiskEngine.validate_vector(base + "/MSI:S")
    assert CVSS4RiskEngine.get_score_nomenclature(m_be_mod) == "CVSS-BE"

    # 4. Base + Threat + Environmental -> CVSS-BTE
    _, _, m_bte = CVSS4RiskEngine.validate_vector(base + "/E:P/CR:H/MSI:S")
    assert CVSS4RiskEngine.get_score_nomenclature(m_bte) == "CVSS-BTE"


def test_score_vulnerability_returns_nomenclature():
    """Ensure score_vulnerability includes score_nomenclature in output."""
    res = CVSS4RiskEngine.score_vulnerability("SQL Injection", category="Injection")
    assert "score_nomenclature" in res
    assert res["score_nomenclature"] == "CVSS-B"
    assert "score_nomenclature" in res["scoring_factors"]


# ==============================================================================
# 8. CANONICAL VECTOR NORMALIZATION & ORDERING
# ==============================================================================

def test_canonical_vector_normalization():
    """Verify normalize_vector orders metrics strictly according to specification."""
    # Out of order vector
    unorder_vec = "CVSS:4.0/SA:N/SI:N/SC:N/VA:H/VI:H/VC:H/UI:N/PR:N/AT:N/AC:L/AV:N/E:P"
    ok, msg, norm_vec = CVSS4RiskEngine.normalize_vector(unorder_vec)
    assert ok is True

    # Expected canonical order starts with AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA, E
    expected_prefix = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P"
    assert norm_vec == expected_prefix


# ==============================================================================
# 9. EQUIVALENCE SETS (EQ1–EQ6) PARAMETRIC COVERAGE
# ==============================================================================

EQ_TEST_CASES = [
    # (vector, expected_macrovector, expected_score, description)
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MSI:S",
        "000000",
        10.0,
        "Absolute Maximum Severity with Safety Impact (EQ1:0, EQ2:0, EQ3:0, EQ4:0 via MSI:S, EQ5:0, EQ6:0)",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "000100",
        10.0,
        "Max Theoretical Base Severity without Safety (EQ1:0, EQ2:0, EQ3:0, EQ4:1 via subsequent H, EQ5:0, EQ6:0)",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "000200",
        9.3,
        "Critical SQLi Base (EQ1:0, EQ2:0, EQ3:0, EQ4:2, EQ5:0, EQ6:0)",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
        "102201",
        5.3,
        "Reflected XSS Base (EQ1:1, EQ2:0, EQ3:2, EQ4:2, EQ5:0, EQ6:1)",
    ),
    (
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N/E:U/CR:L/IR:L/AR:L",
        "212221",
        0.1,
        "Lowest Non-Zero Theoretical Flaw (MacroVector 212221 = 0.1 Low)",
    ),
]


@pytest.mark.parametrize("vector_str,expected_mv,expected_score,desc", EQ_TEST_CASES)
def test_macrovector_and_score_parametric(vector_str, expected_mv, expected_score, desc):
    """Verify exact MacroVector and score across EQ dimensions."""
    ok, msg, metrics = CVSS4RiskEngine.validate_vector(vector_str)
    assert ok is True, f"Failed syntax for {desc}: {msg}"
    mv = CVSS4RiskEngine.compute_macro_vector(metrics)
    assert mv == expected_mv, f"MacroVector mismatch for {desc}: got {mv}, expected {expected_mv}"
    score = CVSS4RiskEngine.calculate_score(metrics)
    assert score == expected_score, f"Score mismatch for {desc}: got {score}, expected {expected_score}"
