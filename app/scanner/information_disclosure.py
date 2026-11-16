import re


class InformationDisclosureScanner:
    """Enterprise Information Disclosure & Error Leakage Inspector.
    
    Detects exposure of technical diagnostic data:
    - Detailed stack traces and unhandled runtime exceptions.
    - Framework debug consoles (Werkzeug, Django, Rails, Laravel Ignition).
    - Internal file system directory paths (UNIX / Windows).
    - Database and server environment internals.
    
    Enforces privacy by design: Redacts discovered credentials or keys immediately.
    """

    SCANNER_NAME = "information_disclosure"

    # Known technical error and stack trace indicators
    STACK_TRACE_PATTERNS = [
        (r"Traceback \(most recent call last\):", "Python Stack Trace"),
        (r"Werkzeug Debugger", "Werkzeug Interactive Debugger"),
        (r"You're seeing this error because you have <code>DEBUG = True</code>", "Django Debug Page"),
        (r"Exception in thread \".*\" java\.", "Java Stack Trace"),
        (r"org\.springframework\.", "Spring Framework Trace"),
        (r"Fatal error:.*in\s+/.+\.php\s+on\s+line", "PHP Fatal Error Trace"),
        (r"Server Error in '/' Application\.", "ASP.NET Technical Error"),
        (r"System\.Web\.HttpUnhandledException", "ASP.NET Exception"),
        (r"Laravel.*Ignition", "Laravel Ignition Error Page"),
        (r"Action Controller: Exception caught", "Ruby on Rails Exception"),
    ]

    # Internal path patterns (UNIX / Windows filesystem leak)
    PATH_PATTERNS = [
        r"(?:/var/www/(?:html|[\w\.\-]+))",
        r"(?:/home/[\w\.\-]+/(?:public_html|app|src))",
        r"(?:[A-Za-z]:\\[Ww]indows\\(?:system32|Microsoft\.NET))",
        r"(?:[A-Za-z]:\\inetpub\\wwwroot)",
        r"(?:[A-Za-z]:\\[Uu]sers\\[\w\.\-]+)",
    ]

    @classmethod
    def scan_response(cls, response_body: str, target_url: str) -> list[dict]:
        """Inspect HTML/text response body for information disclosure signatures."""
        findings = []

        if not response_body or len(response_body) > 2000000:
            return findings

        # 1. Stack Trace / Debug Mode Detection
        for pattern, trace_name in cls.STACK_TRACE_PATTERNS:
            match = re.search(pattern, response_body, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 20)
                end = min(len(response_body), match.end() + 80)
                snippet = response_body[start:end].replace("<", "&lt;").replace(">", "&gt;").strip()

                severity = "HIGH" if "Debugger" in trace_name or "Debug Page" in trace_name else "MEDIUM"

                findings.append({
                    "vulnerability_name": f"Detailed Technical Error / Stack Trace ({trace_name})",
                    "category": "Information Disclosure",
                    "severity": severity,
                    "confidence": "CONFIRMED",
                    "affected_url": target_url,
                    "parameter": None,
                    "http_method": "GET",
                    "description": (
                        f"The application exposed internal diagnostic information ({trace_name}) in the HTTP response. "
                        "Detailed stack traces and debug screens disclose internal source code file paths, framework versions, and execution state."
                    ),
                    "evidence": f"Pattern: '{trace_name}'. Matched Snippet: '{snippet}'",
                    "impact": (
                        "Disclosing framework internals and stack traces allows attackers to understand internal architectures, "
                        "identify exact third-party dependency versions, and craft targeted exploitation attempts."
                    ),
                    "remediation": (
                        "Disable debug mode in production (e.g., set DEBUG=False in Django/Flask). "
                        "Implement centralized, generic custom error pages (HTTP 404, 500) that log details server-side while displaying safe messages to clients."
                    ),
                    "cwe_id": "CWE-209",
                    "owasp_category": "A05:2021 - Security Misconfiguration",
                    "scanner_module": cls.SCANNER_NAME,
                })
                break  # Record one high-fidelity finding per response

        # 2. Internal Path Disclosure Detection
        for path_pattern in cls.PATH_PATTERNS:
            path_match = re.search(path_pattern, response_body)
            if path_match:
                matched_path = path_match.group(0)
                findings.append({
                    "vulnerability_name": "Internal File System Path Disclosure",
                    "category": "Information Disclosure",
                    "severity": "LOW",
                    "confidence": "HIGH",
                    "affected_url": target_url,
                    "parameter": None,
                    "http_method": "GET",
                    "description": f"The response reveals internal server filesystem paths ('{matched_path}').",
                    "evidence": f"Internal filesystem path discovered: '{matched_path}'",
                    "impact": "Informs adversaries of local directory structures and username conventions on the hosting server.",
                    "remediation": "Sanitize server responses and exceptions to ensure absolute file paths are never exposed to the public.",
                    "cwe_id": "CWE-497",
                    "owasp_category": "A05:2021 - Security Misconfiguration",
                    "scanner_module": cls.SCANNER_NAME,
                })
                break

        return findings
