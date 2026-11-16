import re
import secrets
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
import requests
from app.security.target_validator import TargetValidator, TargetValidationError


class XSSScanner:
    """Enterprise Safe Cross-Site Scripting (XSS) Assessment Engine.
    
    Identifies unencoded parameter reflection and contextual injection weaknesses.
    Enforces safe evaluation:
    - Employs harmless unique alphanumeric probes with safe markup tags (e.g., <asprobe>).
    - Strictly avoids executable JavaScript execution or browser popup payloads.
    - Inspects DOM context to distinguish safe HTML entity encoding (&lt;) from raw reflection.
    - Strictly avoids persistent payload injection or mutating form actions.
    """

    SCANNER_NAME = "xss_scanner"
    DEFAULT_TIMEOUT = 5.0
    DEFAULT_USER_AGENT = "AppSentinel-VulnScanner/2.0 (XSS-Audit; +https://appsentinel.local)"

    @classmethod
    def scan_url(
        cls,
        target_url: str,
        timeout: float = DEFAULT_TIMEOUT,
        session: requests.Session = None,
        allow_private: bool = False,
    ) -> list[dict]:
        """Audit URL parameters for unencoded reflection and XSS vulnerabilities."""
        findings = []
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return findings

        try:
            TargetValidator.validate_target_url(target_url, allow_private=allow_private)
        except TargetValidationError:
            return findings

        http = session or requests.Session()
        headers = {"User-Agent": cls.DEFAULT_USER_AGENT}

        for param_name, values in params.items():
            original_val = values[0] if values else ""
            unique_token = f"asprobe_{secrets.token_hex(4)}"
            
            # Safe probe containing unique token and test markup tag
            probe_val = f"<asxss_{unique_token}>"
            test_params = dict(params)
            test_params[param_name] = [probe_val]
            query_str = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_str, parsed.fragment))

            try:
                resp = http.get(test_url, headers=headers, timeout=timeout, allow_redirects=False)
            except requests.RequestException:
                continue

            content_type = resp.headers.get("Content-Type", "").lower()
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                continue

            resp_text = resp.text

            # Check if probe was reflected at all
            if unique_token not in resp_text:
                continue

            # Check if raw unencoded HTML tag was reflected (<asxss_...>)
            raw_tag_reflected = probe_val in resp_text

            # Inspect context using BeautifulSoup
            soup = None
            try:
                soup = BeautifulSoup(resp_text[:1000000], "html.parser")
            except Exception:
                pass

            is_inside_script = False
            is_unencoded_tag = False

            if soup:
                # Check if probe tag was parsed as a DOM element (proves unencoded HTML parsing)
                if soup.find(re.compile(f"^asxss_{unique_token}$", re.I)):
                    is_unencoded_tag = True

                # Check if reflection landed inside an existing <script> block
                for script in soup.find_all("script"):
                    if script.string and unique_token in script.string:
                        is_inside_script = True
                        break

            if is_unencoded_tag or raw_tag_reflected or is_inside_script:
                confidence = "CONFIRMED" if is_unencoded_tag or is_inside_script else "HIGH"
                severity = "HIGH"
                context_desc = "executable HTML/DOM tag context" if is_unencoded_tag else ("inside inline <script> block" if is_inside_script else "raw unencoded response context")

                # Extract a small safe snippet
                idx = resp_text.find(unique_token)
                start = max(0, idx - 40)
                end = min(len(resp_text), idx + 60)
                snippet = resp_text[start:end].replace("<", "&lt;").replace(">", "&gt;")

                findings.append({
                    "vulnerability_name": "Reflected Cross-Site Scripting (XSS)",
                    "category": "Cross-Site Scripting",
                    "severity": severity,
                    "confidence": confidence,
                    "affected_url": target_url,
                    "parameter": param_name,
                    "http_method": "GET",
                    "description": (
                        f"The parameter '{param_name}' reflects unencoded user input into the HTML response body in an {context_desc}. "
                        "Special characters such as '<' and '>' were returned verbatim without contextual HTML entity encoding."
                    ),
                    "evidence": f"Parameter: '{param_name}'. Reflected probe: '{probe_val}'. Context: {context_desc}. Snippet: {snippet}",
                    "impact": (
                        "An attacker could trick a user into clicking a crafted link, executing arbitrary client-side JavaScript "
                        "in their browser session, stealing session tokens, or performing unauthorized actions on their behalf."
                    ),
                    "remediation": (
                        "Implement context-aware output encoding (HTML entity encoding, attribute encoding, or JavaScript encoding) "
                        "before rendering user-supplied data in HTML templates. Utilize template engines with automatic HTML escaping."
                    ),
                    "cwe_id": "CWE-79",
                    "owasp_category": "A03:2021 - Injection",
                    "scanner_module": cls.SCANNER_NAME,
                })
            else:
                # Reflection occurred, but it was safely encoded (e.g. &lt;asxss_...&gt;)
                # Harmless reflection - do not report as a false-positive vulnerability
                pass

        return findings
