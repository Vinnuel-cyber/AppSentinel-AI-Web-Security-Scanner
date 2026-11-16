import re


class SensitiveDataScanner:
    """Enterprise Sensitive Information Exposure Scanner.
    
    Identifies accidentally leaked tokens, cryptographic private keys,
    and database connection strings in public responses.
    
    Strict safety and privacy mandates:
    - Automatically and immediately redacts all discovered secrets.
    - NEVER stores raw or actionable secrets in databases or logs.
    - NEVER attempts authentication or validation with discovered credentials.
    - Enforces a strict response size limit to avoid excessive memory consumption.
    """

    SCANNER_NAME = "sensitive_data_scanner"
    MAX_BODY_SIZE = 1000000  # 1 MB maximum inspection limit

    # Patterns with (Regex, Name, Severity, Confidence)
    SENSITIVE_PATTERNS = [
        (
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
            "Cryptographic Private Key Header",
            "CRITICAL",
            "CONFIRMED",
        ),
        (
            r"(?:AKIA[0-9A-Z]{16})",
            "AWS Access Key ID Pattern",
            "HIGH",
            "HIGH",
        ),
        (
            r"(?:ghp_[A-Za-z0-9_]{36})",
            "GitHub Personal Access Token",
            "CRITICAL",
            "HIGH",
        ),
        (
            r"(?:xox[baprs]-[0-9A-Za-z]{10,48})",
            "Slack API Token Pattern",
            "HIGH",
            "HIGH",
        ),
        (
            r"(?:postgres(?:ql)?|mysql|mongodb)://[\w\.\-]+:[^\s@]+@[\w\.\-]+(?::\d+)?/[^\s\"\'>]+",
            "Database Connection URI with Embedded Credentials",
            "CRITICAL",
            "HIGH",
        ),
        (
            r"(?:(?:SECRET_KEY|API_SECRET|AWS_SECRET_ACCESS_KEY|DB_PASSWORD)\s*=\s*['\"][^\s'\"]{6,}['\"])",
            "Hardcoded Environment Secret String",
            "HIGH",
            "MEDIUM",
        ),
    ]

    @classmethod
    def redact(cls, secret_str: str) -> str:
        """Redact sensitive strings, preserving only beginning/ending markers for triage."""
        if not secret_str:
            return "[REDACTED]"
        if secret_str.startswith("-----BEGIN"):
            return "-----BEGIN [REDACTED]-----"
        if len(secret_str) <= 8:
            return "[REDACTED]"
        # Preserve first 4 and last 2 characters
        return f"{secret_str[:4]}****[REDACTED]****{secret_str[-2:]}"

    @classmethod
    def scan_response(cls, response_body: str, target_url: str) -> list[dict]:
        """Inspect response text for sensitive data patterns with instant redaction."""
        findings = []

        if not response_body or len(response_body) > cls.MAX_BODY_SIZE:
            return findings

        for pattern, pattern_name, severity, confidence in cls.SENSITIVE_PATTERNS:
            matches = list(re.finditer(pattern, response_body))
            if matches:
                first_match = matches[0]
                matched_raw = first_match.group(0)
                redacted_evidence = cls.redact(matched_raw)

                # Contextual location: line number
                line_no = response_body[:first_match.start()].count("\n") + 1

                findings.append({
                    "vulnerability_name": f"Sensitive Information Exposure ({pattern_name})",
                    "category": "Cryptographic Failures",
                    "severity": severity,
                    "confidence": confidence,
                    "affected_url": target_url,
                    "parameter": None,
                    "http_method": "GET",
                    "description": (
                        f"The response body contains patterns matching {pattern_name} near line {line_no}. "
                        "Publicly accessible endpoints must never expose sensitive credentials, private keys, or API tokens."
                    ),
                    "evidence": f"Pattern: '{pattern_name}'. Detected at line {line_no}. Redacted Value: {redacted_evidence}",
                    "impact": (
                        "Exposed credentials could allow adversaries to access cloud accounts, database clusters, "
                        "or third-party SaaS services without authorization."
                    ),
                    "remediation": (
                        "Immediately revoke and rotate the exposed credential or private key. "
                        "Move secrets to environment variables or dedicated secret management services (e.g., HashiCorp Vault, AWS Secrets Manager) "
                        "and ensure debug or configuration responses are not publicly accessible."
                    ),
                    "cwe_id": "CWE-312",
                    "owasp_category": "A02:2021 - Cryptographic Failures",
                    "scanner_module": cls.SCANNER_NAME,
                })

        return findings
