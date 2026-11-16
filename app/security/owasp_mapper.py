from typing import Optional


class OWASPMapper:
    """Enterprise OWASP Top 10 Classification Engine.
    
    Implements deterministic, evidence-grounded taxonomy mapping according to
    the official OWASP Top 10:2021 standard:
    - A01:2021 - Broken Access Control
    - A02:2021 - Cryptographic Failures
    - A03:2021 - Injection
    - A04:2021 - Insecure Design
    - A05:2021 - Security Misconfiguration
    - A06:2021 - Vulnerable and Outdated Components
    - A07:2021 - Identification and Authentication Failures
    - A08:2021 - Software and Data Integrity Failures
    - A09:2021 - Security Logging and Monitoring Failures
    - A10:2021 - Server-Side Request Forgery (SSRF)
    """

    FRAMEWORK_NAME = "OWASP Top 10"
    FRAMEWORK_VERSION = "2021"

    # Official Category Definitions
    CATEGORIES = {
        "A01:2021": "Broken Access Control",
        "A02:2021": "Cryptographic Failures",
        "A03:2021": "Injection",
        "A04:2021": "Insecure Design",
        "A05:2021": "Security Misconfiguration",
        "A06:2021": "Vulnerable and Outdated Components",
        "A07:2021": "Identification and Authentication Failures",
        "A08:2021": "Software and Data Integrity Failures",
        "A09:2021": "Security Logging and Monitoring Failures",
        "A10:2021": "Server-Side Request Forgery (SSRF)",
    }

    @classmethod
    def map_finding(
        cls,
        vulnerability_name: str,
        category: str = "",
        scanner_module: str = "",
        evidence: str = "",
        cwe_id: str = "",
    ) -> dict:
        """Map a single vulnerability finding to the OWASP Top 10:2021 taxonomy."""
        name_lower = vulnerability_name.lower()
        cat_lower = category.lower()
        module_lower = scanner_module.lower()
        cwe_lower = (cwe_id or "").lower()

        primary_code = "A05:2021"
        primary_name = cls.CATEGORIES["A05:2021"]
        secondary_code: Optional[str] = None
        secondary_name: Optional[str] = None
        confidence = "HIGH"
        rationale = ""

        # 1. SQL Injection
        if "sql" in name_lower or "cwe-89" in cwe_lower or "sqli" in module_lower:
            primary_code = "A03:2021"
            primary_name = cls.CATEGORIES[primary_code]
            secondary_code = None
            secondary_name = None
            confidence = "HIGH"
            rationale = (
                "SQL Injection vulnerabilities occur when untrusted input is interpreted as SQL commands. "
                "Classified under A03:2021 - Injection (CWE-89)."
            )

        # 2. Cross-Site Scripting (Reflected XSS)
        elif "cross-site scripting" in name_lower or "xss" in name_lower or "cwe-79" in cwe_lower or "xss" in module_lower:
            primary_code = "A03:2021"
            primary_name = cls.CATEGORIES[primary_code]
            secondary_code = "A05:2021"
            secondary_name = cls.CATEGORIES[secondary_code]
            confidence = "HIGH"
            rationale = (
                "In OWASP Top 10:2021, Cross-Site Scripting is categorized under A03:2021 - Injection (CWE-79). "
                "The lack of Content-Security-Policy or output encoding is secondary to A05:2021 - Security Misconfiguration."
            )

        # 3. Cryptographic Failures & Sensitive Data / Private Keys
        elif (
            "sensitive information" in name_lower
            or "private key" in name_lower
            or "cryptographic" in cat_lower
            or "cwe-312" in cwe_lower
            or "sensitive_data" in module_lower
        ):
            primary_code = "A02:2021"
            primary_name = cls.CATEGORIES[primary_code]
            secondary_code = "A05:2021"
            secondary_name = cls.CATEGORIES[secondary_code]
            confidence = "HIGH"
            rationale = (
                "Accidental exposure of cryptographic keys, API tokens, or cleartext credentials represents "
                "failures in data protection at rest/transit under A02:2021 - Cryptographic Failures (CWE-312)."
            )

        # 4. Directory Listing & Indexing
        elif "directory listing" in name_lower or "cwe-548" in cwe_lower or "directory_listing" in module_lower:
            primary_code = "A01:2021"
            primary_name = cls.CATEGORIES[primary_code]
            secondary_code = "A05:2021"
            secondary_name = cls.CATEGORIES[secondary_code]
            confidence = "HIGH"
            rationale = (
                "Automatic directory indexing allows unauthorized traversal and asset discovery, classified under "
                "A01:2021 - Broken Access Control (CWE-548) and secondary to A05:2021 - Security Misconfiguration."
            )

        # 5. Insecure Cookies (Missing HttpOnly / Secure / SameSite)
        elif "cookie" in name_lower or "cookie_scanner" in module_lower:
            primary_code = "A05:2021"
            primary_name = cls.CATEGORIES[primary_code]
            secondary_code = "A01:2021"
            secondary_name = cls.CATEGORIES[secondary_code]
            confidence = "HIGH"
            rationale = (
                "Omission of defensive cookie flags (HttpOnly, Secure, SameSite) constitutes security misconfiguration "
                "that weakens session access boundaries (A05:2021, secondary A01:2021)."
            )

        # 6. Defensive Security Headers
        elif "defensive header" in name_lower or "content-security-policy" in name_lower or "hsts" in name_lower:
            primary_code = "A05:2021"
            primary_name = cls.CATEGORIES[primary_code]
            secondary_code = None
            secondary_name = None
            confidence = "HIGH"
            rationale = (
                "Missing or suboptimal HTTP security response headers represent unhardened application configurations "
                "under A05:2021 - Security Misconfiguration (CWE-693)."
            )

        # 7. Server Banner & Software Version Disclosure
        elif "version disclosure" in name_lower or "server" in cat_lower or "banner" in name_lower:
            primary_code = "A05:2021"
            primary_name = cls.CATEGORIES[primary_code]
            secondary_code = "A06:2021"
            secondary_name = cls.CATEGORIES[secondary_code]
            confidence = "HIGH"
            rationale = (
                "Exposing precise server banners and framework versions facilitates targeted attacks on vulnerable dependencies "
                "(A05:2021 - Security Misconfiguration, secondary A06:2021 - Vulnerable and Outdated Components)."
            )

        # 8. Stack Traces & Diagnostic Debug Information
        elif "stack trace" in name_lower or "technical error" in name_lower or "information_disclosure" in module_lower:
            primary_code = "A05:2021"
            primary_name = cls.CATEGORIES[primary_code]
            secondary_code = "A04:2021"
            secondary_name = cls.CATEGORIES[secondary_code]
            confidence = "HIGH"
            rationale = (
                "Disclosing unhandled stack traces and runtime debugger screens exposes system internals in violation of "
                "production hardening standards (A05:2021 - Security Misconfiguration, secondary A04:2021 - Insecure Design)."
            )

        # 9. Dangerous HTTP Methods (PUT/DELETE/TRACE)
        elif "dangerous http methods" in name_lower or "cwe-650" in cwe_lower:
            primary_code = "A05:2021"
            primary_name = cls.CATEGORIES[primary_code]
            secondary_code = "A01:2021"
            secondary_name = cls.CATEGORIES[secondary_code]
            confidence = "HIGH"
            rationale = (
                "Enabling administrative HTTP methods like PUT, DELETE, or TRACE without strict authorization represents "
                "A05:2021 - Security Misconfiguration."
            )

        # 10. Ambiguous / Generic Findings
        else:
            primary_code = "A05:2021"
            primary_name = cls.CATEGORIES[primary_code]
            secondary_code = None
            secondary_name = None
            confidence = "LOW"
            rationale = (
                "Finding lacks distinct category markers; conservatively mapped to general security configuration baseline "
                "(A05:2021 - Security Misconfiguration)."
            )

        return {
            "framework_name": cls.FRAMEWORK_NAME,
            "framework_version": cls.FRAMEWORK_VERSION,
            "primary_category_code": primary_code,
            "primary_category_name": primary_name,
            "secondary_category_code": secondary_code,
            "secondary_category_name": secondary_name,
            "confidence": confidence,
            "mapping_rationale": rationale,
        }
