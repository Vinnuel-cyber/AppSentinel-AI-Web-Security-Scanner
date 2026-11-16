import re
import requests
from app.scanner.security_headers import SecurityHeadersAnalyzer


class MisconfigurationScanner:
    """Enterprise Security Misconfiguration Scanner.
    
    Identifies common defensive hardening defects:
    - Missing or misconfigured defensive HTTP response headers (CSP, HSTS, X-Frame-Options, etc.).
    - Verbose server banners and version disclosure (e.g. Apache/2.4.41 (Ubuntu) PHP/7.4.3).
    - Risky HTTP methods enabled (PUT, DELETE, TRACE).
    - Insecure cache control headers on potentially sensitive pages.
    """

    SCANNER_NAME = "misconfiguration_scanner"
    DEFAULT_TIMEOUT = 5.0
    DEFAULT_USER_AGENT = "AppSentinel-VulnScanner/2.0 (Misconfig-Audit; +https://appsentinel.local)"

    @classmethod
    def audit_headers_and_banners(
        cls,
        headers: dict,
        target_url: str,
        is_https: bool = True,
    ) -> list[dict]:
        """Audit HTTP response headers for missing security controls and verbose banners."""
        findings = []

        # 1. Security Headers Audit
        header_evals = SecurityHeadersAnalyzer.evaluate(headers, is_https=is_https)
        for h in header_evals:
            if not h["present"]:
                findings.append({
                    "vulnerability_name": f"Missing Defensive Header: {h['header_name']}",
                    "category": "Security Misconfiguration",
                    "severity": h["risk_level"],
                    "confidence": "CONFIRMED",
                    "affected_url": target_url,
                    "parameter": h["header_name"],
                    "http_method": "GET",
                    "description": f"The target does not enforce the defensive '{h['header_name']}' HTTP response header.",
                    "evidence": f"Header '{h['header_name']}' is absent from server response.",
                    "impact": "Leaves the application exposed to attacks that the browser could otherwise defend against.",
                    "remediation": h["remediation"],
                    "cwe_id": "CWE-693",
                    "owasp_category": "A05:2021 - Security Misconfiguration",
                    "scanner_module": cls.SCANNER_NAME,
                })
            elif h["status"] == "SUBOPTIMAL":
                findings.append({
                    "vulnerability_name": f"Suboptimal Defensive Header: {h['header_name']}",
                    "category": "Security Misconfiguration",
                    "severity": h["risk_level"],
                    "confidence": "CONFIRMED",
                    "affected_url": target_url,
                    "parameter": h["header_name"],
                    "http_method": "GET",
                    "description": f"The defensive header '{h['header_name']}' is set with a suboptimal value.",
                    "evidence": f"Value: '{h['value']}'. Note: {h['remediation']}",
                    "impact": "Weakens the intended security mechanism or provides incomplete protection.",
                    "remediation": h["remediation"],
                    "cwe_id": "CWE-693",
                    "owasp_category": "A05:2021 - Security Misconfiguration",
                    "scanner_module": cls.SCANNER_NAME,
                })

        # 2. Server Banner & Version Disclosure
        server_val = headers.get("Server") or headers.get("server") or ""
        powered_val = headers.get("X-Powered-By") or headers.get("x-powered-by") or ""

        # Check for verbose version strings (e.g. "Apache/2.4.41", "PHP/8.1.2")
        version_pattern = r"(?:[\w\-]+)/(?:\d+\.[\d\.]+)"
        if re.search(version_pattern, server_val):
            findings.append({
                "vulnerability_name": "Server Software Version Disclosure",
                "category": "Information Disclosure",
                "severity": "LOW",
                "confidence": "CONFIRMED",
                "affected_url": target_url,
                "parameter": "Server",
                "http_method": "GET",
                "description": f"The 'Server' response header discloses precise software version numbers: '{server_val}'.",
                "evidence": f"Server: '{server_val}'",
                "impact": "Assists attackers in targeting known public CVE vulnerabilities specific to the disclosed version.",
                "remediation": "Configure your web server to suppress or minimize server version tokens (e.g., 'ServerTokens Prod' in Apache or 'server_tokens off;' in Nginx).",
                "cwe_id": "CWE-200",
                "owasp_category": "A05:2021 - Security Misconfiguration",
                "scanner_module": cls.SCANNER_NAME,
            })

        if powered_val:
            findings.append({
                "vulnerability_name": "X-Powered-By Technology Banner Disclosure",
                "category": "Information Disclosure",
                "severity": "LOW",
                "confidence": "CONFIRMED",
                "affected_url": target_url,
                "parameter": "X-Powered-By",
                "http_method": "GET",
                "description": f"The 'X-Powered-By' header reveals backend technology details: '{powered_val}'.",
                "evidence": f"X-Powered-By: '{powered_val}'",
                "impact": "Aids automated scanners in profiling backend frameworks and libraries.",
                "remediation": "Remove the 'X-Powered-By' header in framework configuration or reverse proxy rules.",
                "cwe_id": "CWE-200",
                "owasp_category": "A05:2021 - Security Misconfiguration",
                "scanner_module": cls.SCANNER_NAME,
            })

        return findings

    @classmethod
    def audit_http_methods(
        cls,
        target_url: str,
        timeout: float = DEFAULT_TIMEOUT,
        session: requests.Session = None,
    ) -> list[dict]:
        """Check for dangerous or unnecessary HTTP methods via safe OPTIONS request."""
        findings = []
        http = session or requests.Session()
        headers = {"User-Agent": cls.DEFAULT_USER_AGENT}

        try:
            resp = http.options(target_url, headers=headers, timeout=timeout, allow_redirects=False)
            allow_header = resp.headers.get("Allow") or resp.headers.get("allow") or ""
            if allow_header:
                allowed_methods = {m.strip().upper() for m in allow_header.split(",")}
                risky_methods = allowed_methods.intersection({"PUT", "DELETE", "TRACE"})
                if risky_methods:
                    findings.append({
                        "vulnerability_name": f"Potentially Dangerous HTTP Methods Enabled ({', '.join(sorted(risky_methods))})",
                        "category": "Security Misconfiguration",
                        "severity": "MEDIUM",
                        "confidence": "CONFIRMED",
                        "affected_url": target_url,
                        "parameter": "Allow",
                        "http_method": "OPTIONS",
                        "description": (
                            f"The endpoint advertises support for sensitive HTTP methods: {', '.join(sorted(risky_methods))}. "
                            "Methods like TRACE can facilitate Cross-Site Tracing (XST), and unauthenticated PUT/DELETE may allow unauthorized file manipulation."
                        ),
                        "evidence": f"OPTIONS Allow Header: '{allow_header}'",
                        "impact": "Could enable Cross-Site Tracing or unauthorized resource creation/deletion if access controls are misconfigured.",
                        "remediation": "Disable unnecessary HTTP verbs (especially TRACE, PUT, and DELETE) in your web server or router configuration.",
                        "cwe_id": "CWE-650",
                        "owasp_category": "A05:2021 - Security Misconfiguration",
                        "scanner_module": cls.SCANNER_NAME,
                    })
        except requests.RequestException:
            pass

        return findings
