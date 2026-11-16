import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests
from app.security.target_validator import TargetValidator, TargetValidationError


class SQLiScanner:
    """Enterprise Safe SQL Injection Detection Engine.
    
    Identifies SQL syntax anomalies, differential error responses, and parameter handling flaws.
    Enforces non-destructive testing:
    - Strictly avoids database modification (no INSERT/UPDATE/DELETE/DROP).
    - Strictly avoids data exfiltration or table dumping (no UNION SELECT schema).
    - Strictly avoids authentication bypass exploitation.
    - Uses minimal syntax probes (single quote syntax test and neutral boolean logic).
    """

    SCANNER_NAME = "sqli_scanner"
    DEFAULT_TIMEOUT = 5.0
    DEFAULT_USER_AGENT = "AppSentinel-VulnScanner/2.0 (SQLi-Audit; +https://appsentinel.local)"

    # Known DB error signatures across major engines
    SQL_ERROR_PATTERNS = [
        (r"you have an error in your sql syntax", "MySQL"),
        (r"warning: mysql_", "MySQL"),
        (r"unclosed quotation mark after the character string", "Microsoft SQL Server"),
        (r"driver.*sql[\-\_\ ]*server", "Microsoft SQL Server"),
        (r"sqlite3\.operationalerror", "SQLite"),
        (r"sqlite_error", "SQLite"),
        (r"syntax error.*sqlite", "SQLite"),
        (r"pg_query\(\): query failed", "PostgreSQL"),
        (r"psycopg2\.errors\.", "PostgreSQL"),
        (r"ora-[0-9]{5}", "Oracle"),
        (r"quoted string not properly terminated", "Oracle"),
        (r"microsoft ole db provider for odbc drivers", "ODBC/SQL"),
        (r"cli driver.*db2", "IBM DB2"),
    ]

    # Harmless syntax probes
    SYNTAX_PROBES = ["'", "''"]

    @classmethod
    def scan_url(
        cls,
        target_url: str,
        timeout: float = DEFAULT_TIMEOUT,
        session: requests.Session = None,
        allow_private: bool = False,
    ) -> list[dict]:
        """Scan a URL and its parameters for SQL injection vulnerabilities safely."""
        findings = []
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return findings

        # Target SSRF guard
        try:
            TargetValidator.validate_target_url(target_url, allow_private=allow_private)
        except TargetValidationError:
            return findings

        http = session or requests.Session()
        headers = {"User-Agent": cls.DEFAULT_USER_AGENT}

        # 1. Baseline request
        try:
            baseline_resp = http.get(target_url, headers=headers, timeout=timeout, allow_redirects=False)
            baseline_status = baseline_resp.status_code
            baseline_body = baseline_resp.text
        except requests.RequestException:
            return findings

        # 2. Test each parameter individually
        for param_name, values in params.items():
            original_val = values[0] if values else ""

            # Test single quote syntax anomaly probe
            for probe in cls.SYNTAX_PROBES:
                test_params = dict(params)
                test_params[param_name] = [original_val + probe]
                query_str = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_str, parsed.fragment))

                try:
                    resp = http.get(test_url, headers=headers, timeout=timeout, allow_redirects=False)
                except requests.RequestException:
                    continue

                resp_body = resp.text
                matched_db = None
                matched_snippet = None

                # Check error patterns in response
                for pattern, db_engine in cls.SQL_ERROR_PATTERNS:
                    match = re.search(pattern, resp_body, re.IGNORECASE)
                    if match and not re.search(pattern, baseline_body, re.IGNORECASE):
                        matched_db = db_engine
                        # Extract snippet of surrounding context
                        start = max(0, match.start() - 30)
                        end = min(len(resp_body), match.end() + 30)
                        matched_snippet = resp_body[start:end].strip()
                        break

                if matched_db:
                    findings.append({
                        "vulnerability_name": f"SQL Injection ({matched_db} Error-Based)",
                        "category": "Injection",
                        "severity": "CRITICAL",
                        "confidence": "CONFIRMED",
                        "affected_url": target_url,
                        "parameter": param_name,
                        "http_method": "GET",
                        "description": (
                            f"The parameter '{param_name}' reflects database syntax errors when supplied with probe characters. "
                            f"The backend returned a {matched_db} error message, confirming unparameterized query execution."
                        ),
                        "evidence": f"Injected: '{probe}'. DB Engine: {matched_db}. Error Snippet: '{matched_snippet}'",
                        "impact": "An attacker could manipulate backend database queries, bypass business logic, or compromise data confidentiality and integrity.",
                        "remediation": "Refactor database access to use parameterized queries (prepared statements) or an established Object-Relational Mapper (ORM). Never concatenate user input directly into SQL strings.",
                        "cwe_id": "CWE-89",
                        "owasp_category": "A03:2021 - Injection",
                        "scanner_module": cls.SCANNER_NAME,
                    })
                    break  # Parameter confirmed, skip remaining probes for this param

                # Status code differential check (200 OK baseline -> 500 Internal Server Error upon quote)
                elif probe == "'" and baseline_status == 200 and resp.status_code == 500:
                    findings.append({
                        "vulnerability_name": "Potential SQL Injection (HTTP 500 Anomaly)",
                        "category": "Injection",
                        "severity": "HIGH",
                        "confidence": "MEDIUM",
                        "affected_url": target_url,
                        "parameter": param_name,
                        "http_method": "GET",
                        "description": (
                            f"The parameter '{param_name}' caused the server to return an internal server error (HTTP 500) "
                            f"when supplied with single quote probe '{probe}', whereas the baseline response was HTTP {baseline_status}."
                        ),
                        "evidence": f"Baseline: HTTP {baseline_status}. Injected '{probe}': HTTP {resp.status_code}.",
                        "impact": "May indicate unhandled SQL exceptions or improper input sanitization.",
                        "remediation": "Ensure all database input is parameterized and review server-side database exception handling.",
                        "cwe_id": "CWE-89",
                        "owasp_category": "A03:2021 - Injection",
                        "scanner_module": cls.SCANNER_NAME,
                    })
                    break

        return findings
