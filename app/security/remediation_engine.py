class RemediationEngine:
    """Enterprise Remediation Guidance Engine.
    
    Generates actionable, specific, and defensive remediation advisories based on
    industry standards (OWASP Cheat Sheet Series, NIST SP 800-53, RFC specifications).
    
    Safety principle: Provides defensive implementation patterns and testing steps;
    never executes destructive actions or automated modifications against target systems.
    """

    REMEDIATION_CATALOG = {
        "sqli": {
            "risk_explanation": (
                "SQL Injection enables adversaries to subvert application logic, manipulate backend queries, "
                "or access unauthorized database records by supplying crafted input into unparameterized statements."
            ),
            "recommended_fix": (
                "Refactor SQL execution to use parameterized queries (prepared statements) or an established Object-Relational "
                "Mapping (ORM) framework. Never interpolate, format, or concatenate user-controlled data into SQL strings."
            ),
            "secure_example": """# Python SQLAlchemy / Prepared Statement Example:
# VULNERABLE: db.session.execute(text(f"SELECT * FROM users WHERE username = '{username}'"))
# SECURE (Parameterized):
stmt = text("SELECT id, username, email FROM users WHERE username = :uname")
result = db.session.execute(stmt, {"uname": username}).first()""",
            "verification_steps": (
                "1. Attempt injecting single quotes, double quotes, and SQL boolean operators into the parameter.\n"
                "2. Verify the server returns normal responses or valid validation errors (HTTP 400), rather than SQL syntax errors (HTTP 500).\n"
                "3. Review the code to confirm parameterized query syntax."
            ),
            "references": [
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/89.html",
            ],
        },
        "xss": {
            "risk_explanation": (
                "Cross-Site Scripting allows attackers to inject malicious scripts into trusted web applications, "
                "enabling cookie theft, credential harvesting, session hijacking, or defacement."
            ),
            "recommended_fix": (
                "Enforce context-sensitive output encoding (HTML entity encoding, attribute encoding) before reflecting user input. "
                "Combine this with a restrictive Content-Security-Policy (CSP) that disables unsafe inline scripts."
            ),
            "secure_example": """<!-- Jinja2 / HTML Escaping Example -->
<!-- VULNERABLE: {{ user_input | safe }} -->
<!-- SECURE: -->
<p>Hello, {{ user_input }}</p> <!-- Autoescaped by Jinja2 by default -->""",
            "verification_steps": (
                "1. Submit benign markup test tokens like <asprobe_test> to the parameter.\n"
                "2. View page source and verify special characters are properly entity-encoded (&lt;asprobe_test&gt;).\n"
                "3. Ensure the browser developer console displays no script execution."
            ),
            "references": [
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/79.html",
            ],
        },
        "cookie": {
            "risk_explanation": (
                "Session cookies lacking HttpOnly can be stolen via XSS. Cookies lacking Secure can be sniffed in cleartext "
                "over unencrypted networks. Cookies lacking SameSite increase exposure to CSRF."
            ),
            "recommended_fix": (
                "Configure all session and authentication cookies with HttpOnly=True, Secure=True, and SameSite='Lax' (or 'Strict')."
            ),
            "secure_example": """# Flask Session Cookie Configuration (config.py):
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = 'Lax'
PERMANENT_SESSION_LIFETIME = timedelta(hours=2)""",
            "verification_steps": (
                "1. Open Browser DevTools -> Storage -> Cookies (or inspect Set-Cookie headers via curl).\n"
                "2. Confirm HttpOnly and Secure checkmarks are present.\n"
                "3. Confirm SameSite is set to Lax or Strict."
            ),
            "references": [
                "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
            ],
        },
        "header": {
            "risk_explanation": (
                "Missing defensive HTTP response headers deprives modern web browsers of critical instructions to "
                "prevent framing/clickjacking, MIME sniffing, and unauthorized script origins."
            ),
            "recommended_fix": (
                "Add defensive HTTP headers via reverse proxy (Nginx/Apache/Cloudflare) or application middleware."
            ),
            "secure_example": """# Nginx Security Headers Configuration:
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self';" always;""",
            "verification_steps": (
                "1. Send an HTTP GET request using curl -I https://target.com.\n"
                "2. Verify X-Content-Type-Options, X-Frame-Options, HSTS, and CSP are present in the response headers."
            ),
            "references": [
                "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html",
                "https://owasp.org/www-project-secure-headers/",
            ],
        },
        "banner": {
            "risk_explanation": (
                "Disclosing exact software version numbers (e.g. Apache/2.4.41, PHP/7.4) accelerates vulnerability research "
                "and automated targeting by malicious actors."
            ),
            "recommended_fix": (
                "Suppress detailed server version tokens and remove X-Powered-By banners in server configuration."
            ),
            "secure_example": """# Nginx (nginx.conf):
server_tokens off;

# Apache (httpd.conf):
ServerTokens Prod
ServerSignature Off""",
            "verification_steps": (
                "1. Execute curl -I https://target.com.\n"
                "2. Confirm the Server header returns generic 'Server: nginx' or 'Server: Apache' without specific patch versions."
            ),
            "references": [
                "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
            ],
        },
        "sensitive": {
            "risk_explanation": (
                "Publicly exposed cryptographic private keys, AWS access keys, or database credentials "
                "allow immediate compromise of cloud infrastructure or data stores."
            ),
            "recommended_fix": (
                "1. Immediately revoke, rotate, and invalidate the exposed secret.\n"
                "2. Remove secrets from source code, public files, and version control.\n"
                "3. Utilize an environment secret management service (HashiCorp Vault, AWS Secrets Manager, or Doppler)."
            ),
            "secure_example": """# Use Environment Variables or Secret Vaults:
import os
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
DATABASE_URL = os.environ.get("DATABASE_URL")""",
            "verification_steps": (
                "1. Confirm the exposed token has been rotated and old credentials deactivated.\n"
                "2. Re-scan the endpoint to verify the secret string no longer appears in response payloads."
            ),
            "references": [
                "https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html",
            ],
        },
        "directory": {
            "risk_explanation": (
                "Directory indexing reveals sensitive files, backups (.bak, .sql), and hidden source assets to anyone browsing."
            ),
            "recommended_fix": (
                "Disable automatic directory listing in web server configurations."
            ),
            "secure_example": """# Apache (httpd.conf / .htaccess):
Options -Indexes

# Nginx:
autoindex off;""",
            "verification_steps": (
                "1. Access the directory path (e.g., https://target.com/files/) via browser or curl.\n"
                "2. Confirm server returns HTTP 403 Forbidden or 404 Not Found instead of file index."
            ),
            "references": [
                "https://cwe.mitre.org/data/definitions/548.html",
            ],
        },
        "default": {
            "risk_explanation": (
                "Identified configuration weakness deviates from established secure baseline recommendations."
            ),
            "recommended_fix": (
                "Review the affected component configuration against the OWASP Secure Coding Practices Guide."
            ),
            "secure_example": None,
            "verification_steps": "Re-execute the scan to verify the condition is resolved.",
            "references": [
                "https://owasp.org/www-project-top-ten/",
            ],
        },
    }

    @classmethod
    def generate_recommendation(
        cls,
        vulnerability_name: str,
        category: str = "",
        affected_url: str = "",
        parameter: str = "",
    ) -> dict:
        """Generate structured remediation recommendation for a vulnerability."""
        name_l = vulnerability_name.lower()
        cat_l = category.lower()

        if "sql" in name_l or "sqli" in cat_l:
            key = "sqli"
        elif "cross-site scripting" in name_l or "xss" in name_l:
            key = "xss"
        elif "cookie" in name_l:
            key = "cookie"
        elif "header" in name_l or "missing" in name_l:
            key = "header"
        elif "banner" in name_l or "version" in name_l:
            key = "banner"
        elif "sensitive" in name_l or "private key" in name_l or "cryptographic" in cat_l:
            key = "sensitive"
        elif "directory" in name_l:
            key = "directory"
        else:
            key = "default"

        meta = cls.REMEDIATION_CATALOG[key]
        component = f"{affected_url} ({parameter})" if parameter else affected_url

        return {
            "vulnerability_name": vulnerability_name,
            "affected_component": component,
            "risk_explanation": meta["risk_explanation"],
            "recommended_fix": meta["recommended_fix"],
            "secure_example": meta["secure_example"],
            "verification_steps": meta["verification_steps"],
            "references": meta["references"],
        }
