from app.security.remediation_engine import RemediationEngine


def test_remediation_output_sqli():
    """Verify SQLi remediation includes prepared statements, verification steps, and OWASP cheat sheet."""
    rem = RemediationEngine.generate_recommendation("SQL Injection (SQLite Error-Based)", category="Injection", affected_url="https://target.test/login", parameter="user")
    assert "parameterized queries" in rem["recommended_fix"]
    assert "text(" in rem["secure_example"] or "Prepared Statement" in rem["secure_example"]
    assert "verification_steps" in rem
    assert any("SQL_Injection_Prevention_Cheat_Sheet" in r for r in rem["references"])


def test_remediation_output_xss():
    """Verify XSS remediation includes context-aware output encoding and Jinja2 example."""
    rem = RemediationEngine.generate_recommendation("Reflected Cross-Site Scripting (XSS)", category="Cross-Site Scripting", affected_url="https://target.test/greet", parameter="name")
    assert "output encoding" in rem["recommended_fix"].lower()
    assert "Jinja2" in rem["secure_example"]
    assert any("Cross_Site_Scripting_Prevention_Cheat_Sheet" in r for r in rem["references"])


def test_remediation_output_cookie():
    """Verify cookie remediation advises HttpOnly, Secure, SameSite with configuration snippet."""
    rem = RemediationEngine.generate_recommendation("Cookie Without HttpOnly Flag ('session_id')", category="Insecure Cookies", affected_url="https://target.test/")
    assert "SESSION_COOKIE_HTTPONLY" in rem["secure_example"]
    assert "SESSION_COOKIE_SECURE" in rem["secure_example"]


def test_remediation_output_sensitive_data():
    """Verify sensitive data remediation recommends immediate rotation and secret vault integration."""
    rem = RemediationEngine.generate_recommendation("Sensitive Information Exposure (AWS Access Key ID Pattern)", category="Cryptographic Failures", affected_url="https://target.test/config")
    assert "rotate" in rem["recommended_fix"].lower()
    assert "Vault" in rem["recommended_fix"] or "Secrets Manager" in rem["recommended_fix"]


def test_remediation_output_directory_listing():
    """Verify directory listing remediation advises web server configuration (Options -Indexes)."""
    rem = RemediationEngine.generate_recommendation("Directory Listing Enabled", category="Information Disclosure", affected_url="https://target.test/uploads/")
    assert "Options -Indexes" in rem["secure_example"] or "autoindex off" in rem["secure_example"]
