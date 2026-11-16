"""AppSentinel Structured AI Response Validator Tests (V8)."""

import json
from app.ai.response_validator import ResponseValidator


def test_clean_raw_output_markdown_fences():
    """Verify markdown ```json ... ``` code blocks are cleanly stripped."""
    raw = "```json\n{\n  \"analysis_type\": \"vulnerability_explanation\"\n}\n```"
    cleaned = ResponseValidator.clean_raw_output(raw)
    assert cleaned.startswith("{")
    assert cleaned.endswith("}")
    assert "```" not in cleaned


def test_validate_valid_response():
    """Verify complete schema passes validation."""
    valid_data = {
        "analysis_type": "vulnerability_explanation",
        "summary": "SQL injection vulnerability detected in search endpoint.",
        "technical_explanation": "Untrusted input concatenated into SQL string.",
        "root_cause": "Improper query construction without parameterization.",
        "impact": "Complete confidentiality breach of the database.",
        "evidence_assessment": "Observed syntax error response on single-quote probe.",
        "exploitability_discussion": "Attacker can read credentials directly.",
        "recommendations": [
            {
                "priority": "Immediate",
                "action": "Use parameterized queries",
                "details": "Refactor all raw SQL queries to use bound parameters.",
                "code_example": "db.session.execute(text('SELECT * FROM users WHERE id=:id'), {'id': uid})",
            }
        ],
        "verification_steps": ["Retest with payload ' OR '1'='1"],
        "limitations": ["Tested only GET parameters."],
        "ai_confidence": "HIGH",
    }
    raw_json = json.dumps(valid_data)
    valid, parsed, err = ResponseValidator.validate_analysis_response(raw_json)

    assert valid is True
    assert parsed is not None
    assert parsed["analysis_type"] == "vulnerability_explanation"
    assert parsed["ai_confidence"] == "HIGH"
    assert len(parsed["recommendations"]) == 1


def test_reject_missing_required_key():
    """Verify schema validator rejects objects missing mandatory keys."""
    invalid_data = {
        "analysis_type": "vulnerability_explanation",
        "summary": "Incomplete schema",
        # missing root_cause, technical_explanation, recommendations, etc.
    }
    valid, parsed, err = ResponseValidator.validate_analysis_response(json.dumps(invalid_data))
    assert valid is False
    assert parsed is None
    assert "Missing required response schema key" in err


def test_reject_malformed_json():
    """Verify validator rejects unparseable JSON text."""
    bad_json = "{ invalid_json: missing_quotes "
    valid, parsed, err = ResponseValidator.validate_analysis_response(bad_json)
    assert valid is False
    assert parsed is None
    assert "JSON parse error" in err


def test_confidence_normalization():
    """Verify invalid confidence levels are defaulted to MEDIUM."""
    data = {
        "analysis_type": "vulnerability_explanation",
        "summary": "Summary",
        "technical_explanation": "Tech exp",
        "root_cause": "Root cause",
        "impact": "Impact",
        "evidence_assessment": "Evidence",
        "recommendations": [],
        "verification_steps": [],
        "limitations": [],
        "ai_confidence": "SUPER_HIGH_CERTAIN",  # invalid
    }
    valid, parsed, err = ResponseValidator.validate_analysis_response(json.dumps(data))
    assert valid is True
    assert parsed["ai_confidence"] == "MEDIUM"


def test_empty_or_nonstring_input():
    """Verify empty or non-string input is handled gracefully."""
    valid, parsed, err = ResponseValidator.validate_analysis_response("")
    assert valid is False
    assert "empty" in err.lower()
