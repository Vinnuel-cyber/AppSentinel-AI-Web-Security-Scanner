from app.security.owasp_mapper import OWASPMapper


# ==============================================================================
# OWASP TOP 10:2025 MAPPING TEST SUITE
# Validates against official OWASP Top 10:2025 standard (https://owasp.org/Top10/2025/)
# ==============================================================================

def test_owasp_2025_default_version():
    """Verify that OWASP Top 10:2025 is the default framework version for new assessments."""
    assert OWASPMapper.DEFAULT_VERSION == "2025"
    assert OWASPMapper.FRAMEWORK_VERSION == "2025"
    mapped_default = OWASPMapper.map_finding("SQL Injection (SQLite Error-Based)")
    assert mapped_default["framework_version"] == "2025"
    assert mapped_default["primary_category_code"] == "A05:2025"


def test_owasp_2025_mapping_sqli():
    """Verify SQL injection maps to A05:2025 - Injection with secondary A02:2025."""
    mapped = OWASPMapper.map_finding("SQL Injection (SQLite Error-Based)", category="Injection", scanner_module="sqli_scanner", cwe_id="CWE-89", version="2025")
    assert mapped["primary_category_code"] == "A05:2025"
    assert mapped["primary_category_name"] == "Injection"
    assert mapped["secondary_category_code"] == "A02:2025"
    assert mapped["secondary_category_name"] == "Security Misconfiguration"
    assert mapped["confidence"] == "HIGH"
    assert mapped["framework_version"] == "2025"
    assert "CWE-89" in mapped["mapping_rationale"]


def test_owasp_2025_mapping_reflected_xss():
    """Verify Reflected XSS maps to A05:2025 - Injection with secondary A02:2025."""
    mapped = OWASPMapper.map_finding("Reflected Cross-Site Scripting (XSS)", category="Cross-Site Scripting", scanner_module="xss_scanner", cwe_id="CWE-79", version="2025")
    assert mapped["primary_category_code"] == "A05:2025"
    assert mapped["primary_category_name"] == "Injection"
    assert mapped["secondary_category_code"] == "A02:2025"
    assert mapped["secondary_category_name"] == "Security Misconfiguration"
    assert mapped["confidence"] == "HIGH"
    assert mapped["framework_version"] == "2025"


def test_owasp_2025_mapping_insecure_cookies():
    """Verify cookie security flaws map to A02:2025 - Security Misconfiguration with secondary A07:2025."""
    mapped = OWASPMapper.map_finding("Cookie Without HttpOnly Flag ('session_id')", category="Insecure Cookies", scanner_module="cookie_scanner", version="2025")
    assert mapped["primary_category_code"] == "A02:2025"
    assert mapped["primary_category_name"] == "Security Misconfiguration"
    assert mapped["secondary_category_code"] == "A07:2025"
    assert mapped["secondary_category_name"] == "Authentication Failures"
    assert mapped["confidence"] == "HIGH"


def test_owasp_2025_mapping_sensitive_data_exposure():
    """Verify private key / token exposure maps to A04:2025 - Cryptographic Failures."""
    mapped = OWASPMapper.map_finding("Sensitive Information Exposure (Cryptographic Private Key Header)", category="Cryptographic Failures", scanner_module="sensitive_data_scanner", version="2025")
    assert mapped["primary_category_code"] == "A04:2025"
    assert mapped["primary_category_name"] == "Cryptographic Failures"
    assert mapped["secondary_category_code"] == "A01:2025"
    assert mapped["confidence"] == "HIGH"


def test_owasp_2025_mapping_directory_listing():
    """Verify directory listing maps to A01:2025 - Broken Access Control."""
    mapped = OWASPMapper.map_finding("Directory Listing Enabled", category="Information Disclosure", scanner_module="directory_listing", cwe_id="CWE-548", version="2025")
    assert mapped["primary_category_code"] == "A01:2025"
    assert mapped["primary_category_name"] == "Broken Access Control"
    assert mapped["secondary_category_code"] == "A02:2025"
    assert mapped["confidence"] == "HIGH"


def test_owasp_2025_mapping_stack_trace_disclosure():
    """Verify stack trace disclosure maps to A10:2025 - Mishandling of Exceptional Conditions."""
    mapped = OWASPMapper.map_finding("Detailed Technical Error / Stack Trace (Python Stack Trace)", category="Information Disclosure", scanner_module="information_disclosure", version="2025")
    assert mapped["primary_category_code"] == "A10:2025"
    assert mapped["primary_category_name"] == "Mishandling of Exceptional Conditions"
    assert mapped["secondary_category_code"] == "A02:2025"
    assert mapped["confidence"] == "HIGH"
    assert "CWE-209" in mapped["mapping_rationale"]


def test_owasp_2025_mapping_server_banner():
    """Verify server banner disclosure maps to A02:2025 - Security Misconfiguration."""
    mapped = OWASPMapper.map_finding("Server Software Version Banner Disclosure", category="Security Misconfiguration", scanner_module="misconfiguration_scanner", version="2025")
    assert mapped["primary_category_code"] == "A02:2025"
    assert mapped["primary_category_name"] == "Security Misconfiguration"
    assert mapped["secondary_category_code"] == "A01:2025"
    assert mapped["confidence"] == "HIGH"


def test_owasp_2025_mapping_ambiguous_finding():
    """Verify ambiguous finding in 2025 maps conservatively to A02:2025 with LOW confidence."""
    mapped = OWASPMapper.map_finding("Unusual Header Formatting Detected", category="Unspecified", scanner_module="custom_audit", version="2025")
    assert mapped["primary_category_code"] == "A02:2025"
    assert mapped["confidence"] == "LOW"
    assert mapped["framework_version"] == "2025"
