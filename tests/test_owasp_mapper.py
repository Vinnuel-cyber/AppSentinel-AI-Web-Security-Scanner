from app.security.owasp_mapper import OWASPMapper


def test_owasp_mapping_sqli():
    """Verify SQL injection maps to A03:2021 - Injection with HIGH confidence."""
    mapped = OWASPMapper.map_finding("SQL Injection (SQLite Error-Based)", category="Injection", scanner_module="sqli_scanner", cwe_id="CWE-89")
    assert mapped["primary_category_code"] == "A03:2021"
    assert mapped["primary_category_name"] == "Injection"
    assert mapped["confidence"] == "HIGH"
    assert mapped["framework_version"] == "2021"
    assert "CWE-89" in mapped["mapping_rationale"]


def test_owasp_mapping_reflected_xss():
    """Verify Reflected XSS maps to A03:2021 - Injection with secondary A05:2021."""
    mapped = OWASPMapper.map_finding("Reflected Cross-Site Scripting (XSS)", category="Cross-Site Scripting", scanner_module="xss_scanner", cwe_id="CWE-79")
    assert mapped["primary_category_code"] == "A03:2021"
    assert mapped["primary_category_name"] == "Injection"
    assert mapped["secondary_category_code"] == "A05:2021"
    assert mapped["confidence"] == "HIGH"


def test_owasp_mapping_insecure_cookies():
    """Verify cookie security flaws map to A05:2021 - Security Misconfiguration."""
    mapped = OWASPMapper.map_finding("Cookie Without HttpOnly Flag ('session_id')", category="Insecure Cookies", scanner_module="cookie_scanner")
    assert mapped["primary_category_code"] == "A05:2021"
    assert mapped["primary_category_name"] == "Security Misconfiguration"
    assert mapped["secondary_category_code"] == "A01:2021"
    assert mapped["confidence"] == "HIGH"


def test_owasp_mapping_sensitive_data_exposure():
    """Verify cryptographic private key / token exposure maps to A02:2021 - Cryptographic Failures."""
    mapped = OWASPMapper.map_finding("Sensitive Information Exposure (Cryptographic Private Key Header)", category="Cryptographic Failures", scanner_module="sensitive_data_scanner")
    assert mapped["primary_category_code"] == "A02:2021"
    assert mapped["primary_category_name"] == "Cryptographic Failures"
    assert mapped["confidence"] == "HIGH"


def test_owasp_mapping_directory_listing():
    """Verify directory listing maps to A01:2021 - Broken Access Control."""
    mapped = OWASPMapper.map_finding("Directory Listing Enabled", category="Information Disclosure", scanner_module="directory_listing", cwe_id="CWE-548")
    assert mapped["primary_category_code"] == "A01:2021"
    assert mapped["primary_category_name"] == "Broken Access Control"
    assert mapped["confidence"] == "HIGH"


def test_owasp_mapping_stack_trace_disclosure():
    """Verify stack trace disclosure maps to A05:2021 with secondary A04:2021."""
    mapped = OWASPMapper.map_finding("Detailed Technical Error / Stack Trace (Python Stack Trace)", category="Information Disclosure", scanner_module="information_disclosure")
    assert mapped["primary_category_code"] == "A05:2021"
    assert mapped["secondary_category_code"] == "A04:2021"
    assert mapped["confidence"] == "HIGH"


def test_owasp_mapping_ambiguous_finding():
    """Verify unknown or unclassified findings map conservatively with LOW confidence."""
    mapped = OWASPMapper.map_finding("Unusual Header Formatting Detected", category="Unspecified", scanner_module="custom_audit")
    assert mapped["primary_category_code"] == "A05:2021"
    assert mapped["confidence"] == "LOW"
    assert "conservatively mapped" in mapped["mapping_rationale"].lower()
