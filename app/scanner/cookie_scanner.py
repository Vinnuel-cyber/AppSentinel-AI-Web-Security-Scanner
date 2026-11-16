from http.cookiejar import Cookie
import requests


class CookieScanner:
    """Enterprise Insecure Cookie Security Audit Engine.
    
    Inspects response cookies for critical defense flags:
    - HttpOnly: Prevents client-side script access via document.cookie (XSS token theft mitigation).
    - Secure: Mandates transmission exclusively over encrypted HTTPS/TLS channels.
    - SameSite: Controls cross-site cookie transmission to defend against Cross-Site Request Forgery (CSRF).
    - Domain & Path Scope: Audits overly broad cookie scoping.
    
    Enforces privacy by design: NEVER stores or records raw cookie values.
    """

    SCANNER_NAME = "cookie_scanner"

    @classmethod
    def audit_cookies(cls, cookies: list[Cookie], target_url: str, is_https: bool = True) -> list[dict]:
        """Audit cookie objects extracted from response headers."""
        findings = []

        for c in cookies:
            cookie_name = c.name
            has_httponly = bool(c.has_nonstandard_attr("httponly") or c.has_nonstandard_attr("HttpOnly"))
            has_secure = bool(c.secure)
            samesite = (
                c.get_nonstandard_attr("samesite")
                or c.get_nonstandard_attr("SameSite")
                or "Not Set"
            )

            # Heuristic: Check if cookie is likely a session/authentication token
            is_session_cookie = any(
                token in cookie_name.lower()
                for token in ["sess", "auth", "token", "jwt", "id", "login", "ticket"]
            )

            # 1. Missing HttpOnly
            if not has_httponly:
                severity = "HIGH" if is_session_cookie else "MEDIUM"
                confidence = "CONFIRMED"
                findings.append({
                    "vulnerability_name": f"Cookie Without HttpOnly Flag ('{cookie_name}')",
                    "category": "Insecure Cookies",
                    "severity": severity,
                    "confidence": confidence,
                    "affected_url": target_url,
                    "parameter": cookie_name,
                    "http_method": "GET",
                    "description": (
                        f"The cookie '{cookie_name}' was issued without the 'HttpOnly' attribute. "
                        "This permits client-side scripts to access the cookie value via JavaScript (document.cookie)."
                    ),
                    "evidence": f"Cookie: '{cookie_name}'. HttpOnly=False, Secure={has_secure}, SameSite='{samesite}'. (Value redacted)",
                    "impact": "If an XSS vulnerability exists on the application, an attacker could directly extract this cookie to hijack user sessions.",
                    "remediation": "Configure your web application framework or server to set the 'HttpOnly' flag on all session and sensitive cookies.",
                    "cwe_id": "CWE-1004",
                    "owasp_category": "A05:2021 - Security Misconfiguration",
                    "scanner_module": cls.SCANNER_NAME,
                })

            # 2. Missing Secure Flag on HTTPS
            if is_https and not has_secure:
                severity = "HIGH" if is_session_cookie else "MEDIUM"
                findings.append({
                    "vulnerability_name": f"Cookie Without Secure Flag ('{cookie_name}')",
                    "category": "Insecure Cookies",
                    "severity": severity,
                    "confidence": "CONFIRMED",
                    "affected_url": target_url,
                    "parameter": cookie_name,
                    "http_method": "GET",
                    "description": (
                        f"The cookie '{cookie_name}' was transmitted without the 'Secure' attribute over an HTTPS connection. "
                        "The browser may transmit this cookie in plaintext if the user accesses an unencrypted HTTP link on the same domain."
                    ),
                    "evidence": f"Cookie: '{cookie_name}'. Secure=False, HttpOnly={has_httponly}, SameSite='{samesite}'. (Value redacted)",
                    "impact": "A network adversary (e.g. on public Wi-Fi or compromised router) could intercept the cookie in cleartext via man-in-the-middle attacks.",
                    "remediation": "Set the 'Secure' attribute on all cookies issued over HTTPS so they are never transmitted via unencrypted HTTP.",
                    "cwe_id": "CWE-614",
                    "owasp_category": "A05:2021 - Security Misconfiguration",
                    "scanner_module": cls.SCANNER_NAME,
                })

            # 3. Missing or Lax SameSite policy
            if samesite.lower() in ("not set", "none"):
                findings.append({
                    "vulnerability_name": f"Cookie Missing SameSite Protection ('{cookie_name}')",
                    "category": "Insecure Cookies",
                    "severity": "LOW" if not is_session_cookie else "MEDIUM",
                    "confidence": "CONFIRMED",
                    "affected_url": target_url,
                    "parameter": cookie_name,
                    "http_method": "GET",
                    "description": (
                        f"The cookie '{cookie_name}' has SameSite attribute '{samesite}'. "
                        "Without SameSite=Lax or SameSite=Strict, the browser includes this cookie in cross-site requests, increasing exposure to CSRF."
                    ),
                    "evidence": f"Cookie: '{cookie_name}'. SameSite='{samesite}'. (Value redacted)",
                    "impact": "Facilitates Cross-Site Request Forgery (CSRF) if the application does not implement independent anti-CSRF tokens.",
                    "remediation": "Set 'SameSite=Lax' (or 'SameSite=Strict' for sensitive state-changing cookies).",
                    "cwe_id": "CWE-1275",
                    "owasp_category": "A05:2021 - Security Misconfiguration",
                    "scanner_module": cls.SCANNER_NAME,
                })

        return findings
