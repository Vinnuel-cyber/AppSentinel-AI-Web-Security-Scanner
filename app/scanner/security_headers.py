class SecurityHeadersAnalyzer:
    """Security Headers Assessment Engine.
    
    Evaluates presence, syntax, and strength of essential defensive HTTP response headers.
    Provides actionable remediation guidance based on OWASP Secure Headers Project.
    """

    CRITICAL_HEADERS = {
        "Content-Security-Policy": {
            "name": "Content-Security-Policy",
            "risk_if_missing": "HIGH",
            "remediation": "Configure a robust Content-Security-Policy (CSP) restricting script, style, and object origins (e.g., default-src 'self').",
        },
        "Strict-Transport-Security": {
            "name": "Strict-Transport-Security",
            "risk_if_missing": "MEDIUM",
            "remediation": "Enable HSTS by sending: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        },
        "X-Content-Type-Options": {
            "name": "X-Content-Type-Options",
            "risk_if_missing": "LOW",
            "remediation": "Prevent MIME-sniffing by setting: X-Content-Type-Options: nosniff",
        },
        "X-Frame-Options": {
            "name": "X-Frame-Options",
            "risk_if_missing": "MEDIUM",
            "remediation": "Prevent clickjacking attacks by setting: X-Frame-Options: DENY or SAMEORIGIN",
        },
        "Referrer-Policy": {
            "name": "Referrer-Policy",
            "risk_if_missing": "LOW",
            "remediation": "Protect sensitive referrer data by configuring: Referrer-Policy: strict-origin-when-cross-origin",
        },
        "Permissions-Policy": {
            "name": "Permissions-Policy",
            "risk_if_missing": "INFO",
            "remediation": "Restrict browser device APIs with: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        },
    }

    @classmethod
    def evaluate(cls, headers: dict, is_https: bool = True) -> list[dict]:
        """Analyze headers and return list of findings."""
        normalized = {k.lower(): v for k, v in headers.items()}
        findings = []

        for header_key, meta in cls.CRITICAL_HEADERS.items():
            lower_key = header_key.lower()
            val = normalized.get(lower_key)

            if not val:
                # Missing header
                risk = meta["risk_if_missing"]
                # If site is not HTTPS, HSTS missing is INFO rather than MEDIUM
                if header_key == "Strict-Transport-Security" and not is_https:
                    risk = "INFO"

                findings.append({
                    "header_name": meta["name"],
                    "present": False,
                    "value": None,
                    "status": "MISSING",
                    "risk_level": risk,
                    "remediation": meta["remediation"],
                })
            else:
                # Present - evaluate strength/suboptimality
                status = "OPTIMAL"
                remediation = None
                risk = "INFO"

                if header_key == "X-Frame-Options":
                    val_upper = val.strip().upper()
                    if val_upper not in ("DENY", "SAMEORIGIN"):
                        status = "SUBOPTIMAL"
                        risk = "LOW"
                        remediation = f"Value '{val}' is deprecated or non-standard. Use DENY or SAMEORIGIN."

                elif header_key == "X-Content-Type-Options":
                    if val.strip().lower() != "nosniff":
                        status = "SUBOPTIMAL"
                        risk = "LOW"
                        remediation = f"Expected 'nosniff', received '{val}'."

                elif header_key == "Content-Security-Policy":
                    if "unsafe-inline" in val or "unsafe-eval" in val:
                        status = "SUBOPTIMAL"
                        risk = "LOW"
                        remediation = "CSP contains 'unsafe-inline' or 'unsafe-eval', weakening XSS mitigation."
                    elif "default-src" not in val and "script-src" not in val:
                        status = "SUBOPTIMAL"
                        risk = "LOW"
                        remediation = "CSP lacks default-src or script-src directive fallback."

                elif header_key == "Strict-Transport-Security":
                    if "max-age" not in val.lower():
                        status = "SUBOPTIMAL"
                        risk = "MEDIUM"
                        remediation = "HSTS header is missing required max-age directive."
                    elif "max-age=0" in val.lower():
                        status = "SUBOPTIMAL"
                        risk = "MEDIUM"
                        remediation = "HSTS max-age is set to 0, which disables HTTPS enforcement."

                findings.append({
                    "header_name": meta["name"],
                    "present": True,
                    "value": val,
                    "status": status,
                    "risk_level": risk,
                    "remediation": remediation,
                })

        return findings
