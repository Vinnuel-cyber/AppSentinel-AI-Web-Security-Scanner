import re


class DirectoryListingScanner:
    """Enterprise Directory Listing & Index Exposure Inspector.
    
    Identifies server directories configured with automatic directory browsing (index generation).
    Strict passive policy:
    - Never brute-forces file or directory paths.
    - Never downloads or fetches arbitrary files.
    - Inspects only existing discovered endpoints and directory paths ending in '/'.
    """

    SCANNER_NAME = "directory_listing"

    DIRECTORY_INDEX_SIGNATURES = [
        (r"<title>\s*Index of\s+/[^<]*</title>", "Apache/Nginx Index of /"),
        (r"<h1>\s*Index of\s+/[^<]*</h1>", "Standard Web Server Directory Index"),
        (r"<title>\s*Directory listing for\s+[^<]*</title>", "Python/Lighttpd Directory Listing"),
        (r"\[To Parent Directory\]", "IIS Directory Browsing"),
        (r"<pre><a href=\"\?C=N;O=D\">Name</a>\s+<a href=\"\?C=M;O=A\">Last modified</a>", "Apache Mod_Autoindex"),
    ]

    @classmethod
    def scan_response(cls, response_body: str, target_url: str) -> list[dict]:
        """Audit an existing response body for directory indexing markers."""
        findings = []

        if not response_body or len(response_body) > 1000000:
            return findings

        for pattern, sig_name in cls.DIRECTORY_INDEX_SIGNATURES:
            match = re.search(pattern, response_body, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 10)
                end = min(len(response_body), match.end() + 30)
                snippet = response_body[start:end].replace("<", "&lt;").replace(">", "&gt;").strip()

                findings.append({
                    "vulnerability_name": "Directory Listing Enabled",
                    "category": "Information Disclosure",
                    "severity": "MEDIUM",
                    "confidence": "CONFIRMED",
                    "affected_url": target_url,
                    "parameter": None,
                    "http_method": "GET",
                    "description": (
                        f"The web server has directory browsing enabled at '{target_url}'. "
                        "When an index file (e.g., index.html) is absent, the web server generates a public listing of all files and folders in that path."
                    ),
                    "evidence": f"Signature: '{sig_name}'. Matched Snippet: '{snippet}'",
                    "impact": (
                        "Allows adversaries to enumerate application assets, discover backup or temporary files (.bak, .swp), "
                        "and inspect unlinked application source code or resources."
                    ),
                    "remediation": (
                        "Disable directory browsing on your web server configuration (e.g., 'Options -Indexes' in Apache, "
                        "'autoindex off;' in Nginx, or disable directory browsing in IIS Manager)."
                    ),
                    "cwe_id": "CWE-548",
                    "owasp_category": "A05:2021 - Security Misconfiguration",
                    "scanner_module": cls.SCANNER_NAME,
                })
                break

        return findings
