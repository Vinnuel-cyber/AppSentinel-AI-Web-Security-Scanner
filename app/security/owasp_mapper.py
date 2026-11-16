from typing import Optional


class OWASPMapper:
    """Enterprise Version-Aware OWASP Top 10 Classification Engine.
    
    Supports both OWASP Top 10:2025 (default for new assessments) and
    OWASP Top 10:2021 (for backward-compatible and historical assessments).
    
    Official OWASP 2025 Categories:
    - A01:2025 - Broken Access Control
    - A02:2025 - Security Misconfiguration
    - A03:2025 - Software Supply Chain Failures
    - A04:2025 - Cryptographic Failures
    - A05:2025 - Injection
    - A06:2025 - Insecure Design
    - A07:2025 - Authentication Failures
    - A08:2025 - Software or Data Integrity Failures
    - A09:2025 - Security Logging and Alerting Failures
    - A10:2025 - Mishandling of Exceptional Conditions
    
    Official OWASP 2021 Categories:
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
    DEFAULT_VERSION = "2025"
    FRAMEWORK_VERSION = "2025"
    SUPPORTED_VERSIONS = ["2025", "2021"]

    CATEGORIES_2025 = {
        "A01:2025": "Broken Access Control",
        "A02:2025": "Security Misconfiguration",
        "A03:2025": "Software Supply Chain Failures",
        "A04:2025": "Cryptographic Failures",
        "A05:2025": "Injection",
        "A06:2025": "Insecure Design",
        "A07:2025": "Authentication Failures",
        "A08:2025": "Software or Data Integrity Failures",
        "A09:2025": "Security Logging and Alerting Failures",
        "A10:2025": "Mishandling of Exceptional Conditions",
    }

    CATEGORIES_2021 = {
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

    # Default category map for backward-compatible attribute access
    CATEGORIES = CATEGORIES_2025

    @classmethod
    def get_categories(cls, version: str = "2025") -> dict:
        """Retrieve category dictionary for a specific framework version."""
        if str(version).strip() == "2021":
            return cls.CATEGORIES_2021
        return cls.CATEGORIES_2025

    @classmethod
    def map_finding(
        cls,
        vulnerability_name: str,
        category: str = "",
        scanner_module: str = "",
        evidence: str = "",
        cwe_id: str = "",
        version: str = "2025",
    ) -> dict:
        """Map a single vulnerability finding to the requested OWASP Top 10 version."""
        clean_version = "2021" if str(version).strip() == "2021" else "2025"

        if clean_version == "2021":
            return cls._map_finding_2021(vulnerability_name, category, scanner_module, evidence, cwe_id)
        else:
            return cls._map_finding_2025(vulnerability_name, category, scanner_module, evidence, cwe_id)

    @classmethod
    def _map_finding_2025(
        cls,
        vulnerability_name: str,
        category: str = "",
        scanner_module: str = "",
        evidence: str = "",
        cwe_id: str = "",
    ) -> dict:
        """Internal mapping logic for OWASP Top 10:2025."""
        name_lower = vulnerability_name.lower()
        cat_lower = category.lower()
        module_lower = scanner_module.lower()
        cwe_lower = (cwe_id or "").lower()

        # 1. SQL Injection -> A05:2025 Injection
        if "sql" in name_lower or "cwe-89" in cwe_lower or "sqli" in module_lower:
            return {
                "framework_name": cls.FRAMEWORK_NAME,
                "framework_version": "2025",
                "primary_category_code": "A05:2025",
                "primary_category_name": cls.CATEGORIES_2025["A05:2025"],
                "secondary_category_code": "A02:2025",
                "secondary_category_name": cls.CATEGORIES_2025["A02:2025"],
                "confidence": "HIGH",
                "mapping_rationale": (
                    "In OWASP Top 10:2025, SQL Injection is categorized under A05:2025 - Injection (CWE-89). "
                    "Untrusted input concatenated into SQL queries is interpreted as commands. "
                    "Database syntax error disclosure secondary to A02:2025 - Security Misconfiguration."
                ),
            }

        # 2. Reflected Cross-Site Scripting -> A05:2025 Injection
        elif "cross-site scripting" in name_lower or "xss" in name_lower or "cwe-79" in cwe_lower or "xss" in module_lower:
            return {
                "framework_name": cls.FRAMEWORK_NAME,
                "framework_version": "2025",
                "primary_category_code": "A05:2025",
                "primary_category_name": cls.CATEGORIES_2025["A05:2025"],
                "secondary_category_code": "A02:2025",
                "secondary_category_name": cls.CATEGORIES_2025["A02:2025"],
                "confidence": "HIGH",
                "mapping_rationale": (
                    "Cross-Site Scripting (XSS) is categorized under A05:2025 - Injection (CWE-79). "
                    "Unsanitized client reflection enables arbitrary JavaScript execution. "
                    "Lack of defensive Content-Security-Policy headers is secondary under A02:2025 - Security Misconfiguration."
                ),
            }

        # 3. Cryptographic Failures & Sensitive Data / Private Keys -> A04:2025 Cryptographic Failures
        elif (
            "sensitive information" in name_lower
            or "private key" in name_lower
            or "cryptographic" in cat_lower
            or "cwe-312" in cwe_lower
            or "sensitive_data" in module_lower
        ):
            return {
                "framework_name": cls.FRAMEWORK_NAME,
                "framework_version": "2025",
                "primary_category_code": "A04:2025",
                "primary_category_name": cls.CATEGORIES_2025["A04:2025"],
                "secondary_category_code": "A01:2025",
                "secondary_category_name": cls.CATEGORIES_2025["A01:2025"],
                "confidence": "HIGH",
                "mapping_rationale": (
                    "Exposure of cryptographic private keys, API secrets, or cleartext credentials represents "
                    "deficiencies in data-in-transit/rest protection under A04:2025 - Cryptographic Failures (CWE-312)."
                ),
            }

        # 4. Insecure Session Cookies -> A02:2025 Security Misconfiguration
        elif "cookie" in name_lower or "insecure cookies" in cat_lower or "cookie_scanner" in module_lower:
            return {
                "framework_name": cls.FRAMEWORK_NAME,
                "framework_version": "2025",
                "primary_category_code": "A02:2025",
                "primary_category_name": cls.CATEGORIES_2025["A02:2025"],
                "secondary_category_code": "A07:2025",
                "secondary_category_name": cls.CATEGORIES_2025["A07:2025"],
                "confidence": "HIGH",
                "mapping_rationale": (
                    "Failure to enforce defensive cookie attributes (HttpOnly, Secure, SameSite) constitutes "
                    "A02:2025 - Security Misconfiguration, with secondary impact under A07:2025 - Authentication Failures (CWE-614, CWE-1004)."
                ),
            }

        # 5. Missing Security Headers -> A02:2025 Security Misconfiguration
        elif "security header" in name_lower or "defensive header" in name_lower or "missing" in name_lower or "cwe-693" in cwe_lower or "cwe-1021" in cwe_lower:
            return {
                "framework_name": cls.FRAMEWORK_NAME,
                "framework_version": "2025",
                "primary_category_code": "A02:2025",
                "primary_category_name": cls.CATEGORIES_2025["A02:2025"],
                "secondary_category_code": None,
                "secondary_category_name": None,
                "confidence": "HIGH",
                "mapping_rationale": (
                    "Omission of defensive HTTP headers (CSP, HSTS, X-Frame-Options) represents an insecure default server setup "
                    "under A02:2025 - Security Misconfiguration (CWE-693)."
                ),
            }

        # 6. Server Banner & Technology Disclosure -> A02:2025 Security Misconfiguration
        elif "banner" in name_lower or "server software version" in name_lower or "version disclosure" in name_lower:
            return {
                "framework_name": cls.FRAMEWORK_NAME,
                "framework_version": "2025",
                "primary_category_code": "A02:2025",
                "primary_category_name": cls.CATEGORIES_2025["A02:2025"],
                "secondary_category_code": "A01:2025",
                "secondary_category_name": cls.CATEGORIES_2025["A01:2025"],
                "confidence": "HIGH",
                "mapping_rationale": (
                    "Broadcasting verbose server and runtime version headers facilitates automated reconnaissance, "
                    "classified as A02:2025 - Security Misconfiguration (CWE-200)."
                ),
            }

        # 7. Diagnostic Stack Trace Disclosure -> A10:2025 Mishandling of Exceptional Conditions
        elif "stack trace" in name_lower or "technical error" in name_lower or "cwe-209" in cwe_lower:
            return {
                "framework_name": cls.FRAMEWORK_NAME,
                "framework_version": "2025",
                "primary_category_code": "A10:2025",
                "primary_category_name": cls.CATEGORIES_2025["A10:2025"],
                "secondary_category_code": "A02:2025",
                "secondary_category_name": cls.CATEGORIES_2025["A02:2025"],
                "confidence": "HIGH",
                "mapping_rationale": (
                    "Unhandled application exceptions leaking stack traces and execution state are classified directly under "
                    "A10:2025 - Mishandling of Exceptional Conditions (CWE-209, CWE-248)."
                ),
            }

        # 8. Open Directory Listing -> A01:2025 Broken Access Control
        elif "directory" in name_lower or "cwe-548" in cwe_lower or "directory_listing" in module_lower:
            return {
                "framework_name": cls.FRAMEWORK_NAME,
                "framework_version": "2025",
                "primary_category_code": "A01:2025",
                "primary_category_name": cls.CATEGORIES_2025["A01:2025"],
                "secondary_category_code": "A02:2025",
                "secondary_category_name": cls.CATEGORIES_2025["A02:2025"],
                "confidence": "HIGH",
                "mapping_rationale": (
                    "Public index listing of server directories allows unauthorized enumeration of application resources, "
                    "categorized under A01:2025 - Broken Access Control (CWE-548)."
                ),
            }

        # 9. Dangerous HTTP Methods -> A02:2025 Security Misconfiguration
        elif "dangerous http" in name_lower or "methods" in name_lower:
            return {
                "framework_name": cls.FRAMEWORK_NAME,
                "framework_version": "2025",
                "primary_category_code": "A02:2025",
                "primary_category_name": cls.CATEGORIES_2025["A02:2025"],
                "secondary_category_code": "A01:2025",
                "secondary_category_name": cls.CATEGORIES_2025["A01:2025"],
                "confidence": "MEDIUM",
                "mapping_rationale": (
                    "Allowing dangerous HTTP methods (PUT, DELETE, TRACE) on public endpoints represents an insecure server configuration "
                    "under A02:2025 - Security Misconfiguration (CWE-749)."
                ),
            }

        # 10. Conservative Default / Ambiguous Finding -> A02:2025
        else:
            return {
                "framework_name": cls.FRAMEWORK_NAME,
                "framework_version": "2025",
                "primary_category_code": "A02:2025",
                "primary_category_name": cls.CATEGORIES_2025["A02:2025"],
                "secondary_category_code": None,
                "secondary_category_name": None,
                "confidence": "LOW",
                "mapping_rationale": (
                    "Unclassified finding conservatively mapped to A02:2025 - Security Misconfiguration pending manual analyst review."
                ),
            }

    @classmethod
    def _map_finding_2021(
        cls,
        vulnerability_name: str,
        category: str = "",
        scanner_module: str = "",
        evidence: str = "",
        cwe_id: str = "",
    ) -> dict:
        """Internal mapping logic for historical OWASP Top 10:2021 standard."""
        name_lower = vulnerability_name.lower()
        cat_lower = category.lower()
        module_lower = scanner_module.lower()
        cwe_lower = (cwe_id or "").lower()

        # 1. SQL Injection -> A03:2021
        if "sql" in name_lower or "cwe-89" in cwe_lower or "sqli" in module_lower:
            return {
                "framework_name": cls.FRAMEWORK_NAME,
                "framework_version": "2021",
                "primary_category_code": "A03:2021",
                "primary_category_name": cls.CATEGORIES_2021["A03:2021"],
                "secondary_category_code": None,
                "secondary_category_name": None,
                "confidence": "HIGH",
                "mapping_rationale": (
                    "SQL Injection vulnerabilities occur when untrusted input is interpreted as SQL commands. "
                    "Classified under A03:2021 - Injection (CWE-89)."
                ),
            }

        # 2. Reflected Cross-Site Scripting -> A03:2021
        elif "cross-site scripting" in name_lower or "xss" in name_lower or "cwe-79" in cwe_lower or "xss" in module_lower:
            return {
                "framework_name": cls.FRAMEWORK_NAME,
                "framework_version": "2021",
                "primary_category_code": "A03:2021",
                "primary_category_name": cls.CATEGORIES_2021["A03:2021"],
                "secondary_category_code": "A05:2021",
                "secondary_category_name": cls.CATEGORIES_2021["A05:2021"],
                "confidence": "HIGH",
                "mapping_rationale": (
                    "In OWASP Top 10:2021, Cross-Site Scripting is categorized under A03:2021 - Injection (CWE-79). "
                    "The lack of Content-Security-Policy or output encoding is secondary to A05:2021 - Security Misconfiguration."
                ),
            }

        # 3. Cryptographic Failures & Sensitive Data / Private Keys -> A02:2021
        elif (
            "sensitive information" in name_lower
            or "private key" in name_lower
            or "cryptographic" in cat_lower
            or "cwe-312" in cwe_lower
            or "sensitive_data" in module_lower
        ):
            return {
                "framework_name": cls.FRAMEWORK_NAME,
                "framework_version": "2021",
                "primary_category_code": "A02:2021",
                "primary_category_name": cls.CATEGORIES_2021["A02:2021"],
                "secondary_category_code": "A05:2021",
                "secondary_category_name": cls.CATEGORIES_2021["A05:2021"],
                "confidence": "HIGH",
                "mapping_rationale": (
                    "Accidental exposure of cryptographic keys, API tokens, or cleartext credentials represents "
                    "failures in data protection at rest/transit under A02:2021 - Cryptographic Failures (CWE-312)."
                ),
            }

        # 4. Insecure Session Cookies -> A05:2021
        elif "cookie" in name_lower or "insecure cookies" in cat_lower or "cookie_scanner" in module_lower:
            return {
                "framework_name": cls.FRAMEWORK_NAME,
                "framework_version": "2021",
                "primary_category_code": "A05:2021",
                "primary_category_name": cls.CATEGORIES_2021["A05:2021"],
                "secondary_category_code": "A01:2021",
                "secondary_category_name": cls.CATEGORIES_2021["A01:2021"],
                "confidence": "HIGH",
                "mapping_rationale": (
                    "Missing HttpOnly, Secure, or SameSite cookie attributes represents insecure session state management under "
                    "A05:2021 - Security Misconfiguration (CWE-614, CWE-1004)."
                ),
            }

        # 5. Missing Security Headers -> A05:2021
        elif "security header" in name_lower or "defensive header" in name_lower or "missing" in name_lower or "cwe-693" in cwe_lower or "cwe-1021" in cwe_lower:
            return {
                "framework_name": cls.FRAMEWORK_NAME,
                "framework_version": "2021",
                "primary_category_code": "A05:2021",
                "primary_category_name": cls.CATEGORIES_2021["A05:2021"],
                "secondary_category_code": None,
                "secondary_category_name": None,
                "confidence": "HIGH",
                "mapping_rationale": (
                    "Omission of standard defensive HTTP response headers constitutes "
                    "A05:2021 - Security Misconfiguration (CWE-693)."
                ),
            }

        # 6. Server Banner Disclosure -> A05:2021
        elif "banner" in name_lower or "server software version" in name_lower or "version disclosure" in name_lower:
            return {
                "framework_name": cls.FRAMEWORK_NAME,
                "framework_version": "2021",
                "primary_category_code": "A05:2021",
                "primary_category_name": cls.CATEGORIES_2021["A05:2021"],
                "secondary_category_code": "A01:2021",
                "secondary_category_name": cls.CATEGORIES_2021["A01:2021"],
                "confidence": "HIGH",
                "mapping_rationale": (
                    "Broadcasting server and runtime banner versions aids attacker reconnaissance under "
                    "A05:2021 - Security Misconfiguration (CWE-200)."
                ),
            }

        # 7. Stack Trace Disclosure -> A05:2021
        elif "stack trace" in name_lower or "technical error" in name_lower or "cwe-209" in cwe_lower:
            return {
                "framework_name": cls.FRAMEWORK_NAME,
                "framework_version": "2021",
                "primary_category_code": "A05:2021",
                "primary_category_name": cls.CATEGORIES_2021["A05:2021"],
                "secondary_category_code": "A04:2021",
                "secondary_category_name": cls.CATEGORIES_2021["A04:2021"],
                "confidence": "HIGH",
                "mapping_rationale": (
                    "Detailed technical errors or stack traces leaked in HTTP responses expose internal paths and architecture under "
                    "A05:2021 - Security Misconfiguration (CWE-209)."
                ),
            }

        # 8. Directory Listing -> A01:2021
        elif "directory" in name_lower or "cwe-548" in cwe_lower or "directory_listing" in module_lower:
            return {
                "framework_name": cls.FRAMEWORK_NAME,
                "framework_version": "2021",
                "primary_category_code": "A01:2021",
                "primary_category_name": cls.CATEGORIES_2021["A01:2021"],
                "secondary_category_code": "A05:2021",
                "secondary_category_name": cls.CATEGORIES_2021["A05:2021"],
                "confidence": "HIGH",
                "mapping_rationale": (
                    "Unrestricted indexing of web directories allows unauthorized file enumeration under "
                    "A01:2021 - Broken Access Control (CWE-548)."
                ),
            }

        # 9. Dangerous HTTP Methods -> A05:2021
        elif "dangerous http" in name_lower or "methods" in name_lower:
            return {
                "framework_name": cls.FRAMEWORK_NAME,
                "framework_version": "2021",
                "primary_category_code": "A05:2021",
                "primary_category_name": cls.CATEGORIES_2021["A05:2021"],
                "secondary_category_code": "A01:2021",
                "secondary_category_name": cls.CATEGORIES_2021["A01:2021"],
                "confidence": "MEDIUM",
                "mapping_rationale": (
                    "Enabling arbitrary HTTP methods on public endpoints represents an insecure configuration under "
                    "A05:2021 - Security Misconfiguration (CWE-749)."
                ),
            }

        # 10. Conservative Default / Ambiguous -> A05:2021
        else:
            return {
                "framework_name": cls.FRAMEWORK_NAME,
                "framework_version": "2021",
                "primary_category_code": "A05:2021",
                "primary_category_name": cls.CATEGORIES_2021["A05:2021"],
                "secondary_category_code": None,
                "secondary_category_name": None,
                "confidence": "LOW",
                "mapping_rationale": (
                    "Unclassified finding conservatively mapped to A05:2021 - Security Misconfiguration pending manual review."
                ),
            }
