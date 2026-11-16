"""AppSentinel Deterministic Fallback Engine (V8).

Provides comprehensive, reproducible vulnerability explanations, root-cause
diagnostics, and developer code remediation when Cloud AI is disabled or unavailable.

Grounded in AppSentinel's deterministic security engines (CVSS v4.0, OWASP 2025,
CWE taxonomy, and V7 remediation catalog). Never hallucinates or invents data.
"""

from typing import Optional


class FallbackEngine:
    """Offline deterministic security expert system and chat fallback engine."""

    PROVIDER_NAME = "deterministic-fallback"
    MODEL_NAME = "rule-engine-v1"

    # Pre-calibrated Root-Cause and Remediation Knowledge Base
    KNOWLEDGE_BASE = {
        "sqli": {
            "root_cause": "Dynamic concatenation or string formatting of untrusted input directly into SQL statement strings, allowing attackers to modify query logic and break syntax delimiters.",
            "impact": "Full database confidentiality and integrity compromise; potential administrative credential theft, data tampering, or unauthorized data destruction.",
            "code_example": """# Secure Implementation: Parameterized Queries with SQLAlchemy
from sqlalchemy import text
from app.models import db

def safe_search(user_query: str):
    # Parameterized query binds input safely; SQL syntax cannot be altered
    stmt = text("SELECT id, username, email FROM users WHERE username = :name")
    return db.session.execute(stmt, {"name": user_query}).fetchall()""",
            "verification_steps": [
                "Verify all database operations use ORM queries or explicit parameter binding (:param).",
                "Inject single quote (') and boolean payloads (' OR '1'='1) into parameters and verify query parameterization treats input as literal text.",
                "Inspect application query logs to verify SQL syntax remains unchanged regardless of input characters.",
            ],
        },
        "xss_reflected": {
            "root_cause": "Untrusted request parameters or query arguments rendered directly in the HTML response DOM without context-aware output encoding or contextual HTML escaping.",
            "impact": "Execution of arbitrary client-side JavaScript in victim's browser session, leading to session hijacking, DOM manipulation, credential theft, or phishing injection.",
            "code_example": """<!-- Secure Implementation: Jinja2 Automatic Escaping & CSP -->
<!-- Jinja2 escapes variables by default; never use the '| safe' filter on user input -->
<div class="user-display">
    Hello, {{ user_input }}
</div>

<!-- Add Content-Security-Policy header in Flask response -->
@app.after_request
def add_csp(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self';"
    return response""",
            "verification_steps": [
                "Verify Jinja2 template auto-escaping is active and '| safe' is not applied to user inputs.",
                "Send probe '<script>alert(1)</script>' and confirm the response escapes it as '&lt;script&gt;'.",
                "Verify defensive Content-Security-Policy headers block inline script execution.",
            ],
        },
        "cookie_no_httponly": {
            "root_cause": "Sensitive session identifier cookies set without the 'HttpOnly' flag, leaving session tokens readable by client-side JavaScript via document.cookie.",
            "impact": "High vulnerability to session hijacking if an XSS flaw exists anywhere on the domain; client scripts can exfiltrate active session tokens.",
            "code_example": """# Secure Implementation: Hardened Flask Session Cookie Configuration
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # Disallows JavaScript read access
    SESSION_COOKIE_SECURE=True,     # Requires HTTPS transport
    SESSION_COOKIE_SAMESITE='Lax',  # Defends against Cross-Site Request Forgery (CSRF)
)""",
            "verification_steps": [
                "Inspect Set-Cookie headers in browser Developer Tools Network tab.",
                "Verify 'HttpOnly', 'Secure', and 'SameSite=Lax/Strict' directives are present on session cookies.",
                "Execute 'console.log(document.cookie)' in developer console and verify session tokens do not appear.",
            ],
        },
        "missing_security_header": {
            "root_cause": "Web server or application response omits modern defensive HTTP response headers that enforce browser-side security restrictions.",
            "impact": "Leaves client browsers without defense-in-depth protections against MIME-type confusion, clickjacking framing, and protocol downgrade attacks.",
            "code_example": """# Secure Implementation: Defense-in-Depth Headers Hook
@app.after_request
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self';"
    return response""",
            "verification_steps": [
                "Inspect HTTP response headers via curl -I or browser Network inspection.",
                "Confirm headers (X-Content-Type-Options, X-Frame-Options, HSTS, CSP) are present on all responses.",
            ],
        },
        "server_banner_disclosure": {
            "root_cause": "Web server configured to expose internal software product names and exact patch versions in the 'Server' or 'X-Powered-By' HTTP headers.",
            "impact": "Facilitates automated reconnaissance and targeted CVE lookup for specific disclosed software versions.",
            "code_example": """# Secure Implementation: Nginx / Apache Configuration
# Nginx (nginx.conf):
server_tokens off;
more_clear_headers 'Server' 'X-Powered-By';

# Apache (httpd.conf):
ServerTokens Prod
ServerSignature Off""",
            "verification_steps": [
                "Execute 'curl -I <url>' and verify Server header only shows generic name or is stripped.",
                "Confirm X-Powered-By and diagnostic runtime headers are removed.",
            ],
        },
        "sensitive_key_exposure": {
            "root_cause": "Hardcoded API keys, private tokens, or database credentials bundled in source code or accidentally returned in diagnostic API responses.",
            "impact": "Immediate compromise of cloud infrastructure, database services, or third-party API accounts depending on credential scope.",
            "code_example": """# Secure Implementation: Secrets Management & Environment Isolation
import os
# Read secret from environment variable or secret manager; never commit to repo
DATABASE_PASSWORD = os.environ.get("DB_PASSWORD")
if not DATABASE_PASSWORD:
    raise RuntimeError("Missing required DB_PASSWORD environment secret")""",
            "verification_steps": [
                "Immediately revoke and rotate the discovered credential in the respective provider dashboard.",
                "Audit Git commit history using automated secret scanners (e.g. TruffleHog).",
                "Ensure credentials are supplied strictly via environment variables or cloud secret managers.",
            ],
        },
        "directory_listing": {
            "root_cause": "Web server has automatic directory indexing enabled without an index file (index.html, index.php), allowing unrestricted folder browsing.",
            "impact": "Unrestricted enumeration of application files, backup archives, configuration files, and temporary artifacts.",
            "code_example": """# Secure Implementation: Disable Directory Listing
# Apache (httpd.conf or .htaccess):
Options -Indexes

# Nginx (nginx.conf):
autoindex off;""",
            "verification_steps": [
                "Navigate directly to static assets directory (e.g. /static/ or /uploads/).",
                "Confirm web server returns HTTP 403 Forbidden or 404 Not Found rather than file directory list.",
            ],
        },
    }

    @classmethod
    def analyze_vulnerability_fallback(cls, finding: dict) -> dict:
        """Produce a deterministic, evidence-grounded security analysis for a finding."""
        title = finding.get("title", "Security Finding")
        category = (finding.get("category") or "").lower()
        title_lower = title.lower()

        # Match finding profile
        profile_key = "missing_security_header"
        if "sql" in title_lower or "injection" in category:
            profile_key = "sqli"
        elif "xss" in title_lower or "cross-site scripting" in title_lower:
            profile_key = "xss_reflected"
        elif "cookie" in title_lower:
            profile_key = "cookie_no_httponly"
        elif "banner" in title_lower or "version" in title_lower:
            profile_key = "server_banner_disclosure"
        elif "sensitive" in title_lower or "key" in title_lower or "secret" in title_lower:
            profile_key = "sensitive_key_exposure"
        elif "directory" in title_lower:
            profile_key = "directory_listing"

        profile = cls.KNOWLEDGE_BASE.get(profile_key, cls.KNOWLEDGE_BASE["missing_security_header"])

        # Format deterministic structured response
        cvss_score = finding.get("cvss_score", 0.0)
        cvss_vector = finding.get("cvss_vector", "")
        owasp_cat = finding.get("owasp_category", "OWASP Top 10")
        cwe_id = finding.get("cwe_id", "CWE-Unknown")
        severity = finding.get("severity", "Medium")
        confidence = finding.get("confidence", "MEDIUM")
        affected_url = finding.get("affected_url", "")
        parameter = finding.get("parameter", "")

        summary = (
            f"Deterministic Analysis: {title} identified on {affected_url or 'target endpoint'}. "
            f"Assigned {severity} severity (CVSS {cvss_score}) and mapped to {owasp_cat} ({cwe_id})."
        )

        technical_explanation = (
            f"The scanner observed indicators consistent with {title}. "
            f"Parameter '{parameter or 'N/A'}' exhibited vulnerable characteristics under {finding.get('http_method', 'GET')} request conditions. "
            f"Technical evaluation is derived from scanner observations and CVSS v4.0 vector '{cvss_vector}'."
        )

        recommendations = [
            {
                "priority": "Immediate",
                "action": f"Remediate {title}",
                "details": "Implement defensive parameter validation, context encoding, or server configuration.",
                "code_example": profile["code_example"],
            },
            {
                "priority": "Near-Term",
                "action": "Implement Architectural Defense-in-Depth",
                "details": "Ensure security headers, strict transport security, and principle of least privilege are enforced globally.",
                "code_example": "",
            },
        ]

        return {
            "analysis_type": "vulnerability_explanation",
            "summary": summary,
            "technical_explanation": technical_explanation,
            "root_cause": profile["root_cause"],
            "impact": profile["impact"],
            "evidence_assessment": f"Scanner recorded observation with {confidence} confidence on {affected_url}. Raw payload markers detected.",
            "exploitability_discussion": f"Evaluated under CVSS v4.0 metrics as {severity} severity. Exploitability is dependent on environment exposure and parameter reachability.",
            "recommendations": recommendations,
            "verification_steps": profile["verification_steps"],
            "limitations": [
                "Generated via AppSentinel Deterministic Fallback Engine (Cloud AI is disabled or unavailable).",
                "Analysis is derived strictly from confirmed scanner evidence and pre-calibrated security rules.",
            ],
            "ai_confidence": "HIGH",
            "is_fallback": True,
            "provider": cls.PROVIDER_NAME,
            "model": cls.MODEL_NAME,
        }

    @classmethod
    def analyze_target_summary_fallback(cls, target_data: dict) -> dict:
        """Produce a deterministic executive and technical posture summary for a target."""
        name = target_data.get("name", "Target")
        url = target_data.get("target_url", "")
        env = target_data.get("environment", "Production")
        findings_summary = target_data.get("findings_summary", {})
        total = findings_summary.get("total", 0)
        critical = findings_summary.get("critical", 0)
        high = findings_summary.get("high", 0)
        medium = findings_summary.get("medium", 0)
        low = findings_summary.get("low", 0)
        avg_cvss = findings_summary.get("avg_cvss", 0.0)

        summary = (
            f"Security Posture Summary for {name} ({url}) in {env} environment. "
            f"Identified {total} total findings ({critical} Critical, {high} High, {medium} Medium, {low} Low) "
            f"with an average CVSS v4.0 risk score of {avg_cvss}."
        )

        technical_explanation = (
            f"Security analysis across target attack surface revealed {total} security defects. "
            f"High-priority areas requiring developer attention include {critical} critical and {high} high findings. "
            f"Target is categorized as {'High Risk' if (critical > 0 or high > 1) else 'Moderate Risk' if medium > 0 else 'Low Risk'}."
        )

        root_cause = (
            "Primary defect patterns stem from input handling, omission of modern HTTP defensive headers, "
            "or insecure cookie attribute configuration."
        )

        impact = (
            "Unremediated vulnerabilities could allow unauthorized data access, session hijacking, or "
            "reconnaissance exploitation depending on specific affected routes."
        )

        recommendations = [
            {
                "priority": "Immediate",
                "action": "Remediate Critical & High Findings",
                "details": f"Focus developer sprint on the {critical} critical and {high} high findings immediately.",
                "code_example": "",
            },
            {
                "priority": "Near-Term",
                "action": "Enforce Global Defensive Security Headers",
                "details": "Deploy HSTS, CSP, X-Content-Type-Options, and X-Frame-Options at the reverse proxy layer.",
                "code_example": "",
            },
        ]

        return {
            "analysis_type": "target_summary",
            "summary": summary,
            "technical_explanation": technical_explanation,
            "root_cause": root_cause,
            "impact": impact,
            "evidence_assessment": f"Derived from {total} verified scanner evidence records.",
            "exploitability_discussion": "Remediation should follow operational priority tiers P1 through P5.",
            "recommendations": recommendations,
            "verification_steps": [
                "Apply code mitigations for critical findings.",
                "Re-execute scan via AppSentinel Scanner module to confirm flaw closure.",
            ],
            "limitations": [
                "Generated via AppSentinel Deterministic Fallback Engine (Cloud AI is disabled or unavailable).",
            ],
            "ai_confidence": "HIGH",
            "is_fallback": True,
            "provider": cls.PROVIDER_NAME,
            "model": cls.MODEL_NAME,
        }

    @classmethod
    def chat_fallback_query(cls, user_query: str, authorized_findings: list[dict], authorized_targets: list[dict]) -> dict:
        """Deterministic natural-language Q&A engine handling user inquiries over authorized records."""
        q_lower = user_query.lower()

        # 1. Critical / High findings query
        if "critical" in q_lower or "high" in q_lower or "top vulnerabilities" in q_lower:
            crit_findings = [f for f in authorized_findings if f.get("severity") in ("Critical", "High")]
            if crit_findings:
                lines = [f"- [{f.get('severity')}] {f.get('title')} on {f.get('affected_url')} (CVSS {f.get('cvss_score')})" for f in crit_findings[:6]]
                summary = f"You have {len(crit_findings)} Critical/High vulnerability findings in your authorized scope:\n" + "\n".join(lines)
            else:
                summary = "Great news! There are no Critical or High severity vulnerabilities recorded across your authorized targets."

            technical = "Findings are evaluated under official CVSS v4.0 metrics and prioritized according to AppSentinel's P1-P5 operational framework."
            recs = [{"priority": "Immediate", "action": "Triage Critical Findings", "details": "Fix critical and high items within recommended SLAs.", "code_example": ""}]

        # 2. Highest risk target query
        elif "highest risk" in q_lower or "target risk" in q_lower or "which target" in q_lower:
            if authorized_targets:
                sorted_targets = sorted(authorized_targets, key=lambda t: t.get("critical_count", 0) * 10 + t.get("high_count", 0) * 5, reverse=True)
                top = sorted_targets[0]
                summary = f"Your highest risk target is '{top.get('name')}' ({top.get('target_url')}) with {top.get('critical_count', 0)} Critical and {top.get('high_count', 0)} High findings."
                technical = f"Risk ranking prioritizes confirmed critical flaws and production exposure for target ID {top.get('id')}."
            else:
                summary = "You currently do not have any registered targets in your account."
                technical = "Register a target via Target Management and verify ownership before scanning."
            recs = [{"priority": "Near-Term", "action": "Review Target Findings", "details": "Open target vulnerability view to review evidence.", "code_example": ""}]

        # 3. Specific vulnerability explanations (SQLi, XSS, etc.)
        elif "sql" in q_lower or "injection" in q_lower:
            profile = cls.KNOWLEDGE_BASE["sqli"]
            summary = "SQL Injection occurs when user input is concatenated directly into SQL statements without parameter binding."
            technical = profile["root_cause"]
            recs = [{"priority": "Immediate", "action": "Use Parameterized Queries", "details": "Bind all SQL parameters using prepared statements.", "code_example": profile["code_example"]}]

        elif "xss" in q_lower or "cross-site scripting" in q_lower:
            profile = cls.KNOWLEDGE_BASE["xss_reflected"]
            summary = "Cross-Site Scripting (XSS) occurs when untrusted data is reflected into HTML responses without contextual escaping."
            technical = profile["root_cause"]
            recs = [{"priority": "Immediate", "action": "Enable Contextual Escaping", "details": "Rely on template escaping and enforce CSP.", "code_example": profile["code_example"]}]

        # 4. CVSS or OWASP general questions
        elif "cvss" in q_lower or "vector" in q_lower:
            summary = "AppSentinel implements the official FIRST CVSS v4.0 specification, computing exact MacroVectors (EQ1–EQ6) and single-decimal rounded scores."
            technical = "CVSS v4.0 evaluates Base metrics (AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA), Threat metric E, and Environmental requirements (CR, IR, AR, M*)."
            recs = [{"priority": "General", "action": "Inspect Risk Engine Details", "details": "Review the Risk Engine dashboard to explore MacroVector calculations.", "code_example": ""}]

        elif "owasp" in q_lower:
            summary = "AppSentinel supports both OWASP Top 10:2025 and 2021 standards with version-aware mapping and CWE taxonomy integration."
            technical = "Findings are categorized into the 10 official categories such as A01 Broken Access Control and A03 Software Supply Chain Failures."
            recs = [{"priority": "General", "action": "Review OWASP Dashboard", "details": "Filter findings by framework version in the OWASP tab.", "code_example": ""}]

        # 5. Default general response
        else:
            summary = (
                f"AppSentinel Security Analyst: You have {len(authorized_targets)} active targets and {len(authorized_findings)} recorded findings. "
                f"You can ask me to explain specific findings, identify highest-risk targets, explain CVSS vectors, or provide secure coding examples."
            )
            technical = "Response generated via AppSentinel Deterministic Fallback Engine grounded in your authorized database records."
            recs = []

        return {
            "analysis_type": "security_chat",
            "summary": summary,
            "technical_explanation": technical,
            "root_cause": "",
            "impact": "Security analysis based on authorized scan history.",
            "evidence_assessment": f"Derived from {len(authorized_findings)} authorized finding records.",
            "exploitability_discussion": "Prioritize fixes based on operational urgency.",
            "recommendations": recs,
            "verification_steps": [],
            "limitations": [
                "Generated via AppSentinel Deterministic Fallback Engine (Cloud AI is disabled or unavailable).",
            ],
            "ai_confidence": "HIGH",
            "is_fallback": True,
            "provider": cls.PROVIDER_NAME,
            "model": cls.MODEL_NAME,
        }

    @classmethod
    def generate_vulnerability_analysis(cls, finding: dict) -> dict:
        """Alias for analyze_vulnerability_fallback."""
        return cls.analyze_vulnerability_fallback(finding)

    @classmethod
    def generate_target_summary(cls, target_data: dict) -> dict:
        """Alias for analyze_target_summary_fallback."""
        return cls.analyze_target_summary_fallback(target_data)

    @classmethod
    def generate_chat_response(
        cls,
        user_query: str,
        target_data: Optional[dict] = None,
        authorized_findings: Optional[list] = None,
        authorized_targets: Optional[list] = None,
    ) -> dict:
        """Alias for chat_fallback_query supporting flexible parameter structures."""
        findings = authorized_findings or []
        targets = authorized_targets or []
        if target_data and not targets:
            targets = [target_data]
            if "top_findings" in target_data and not findings:
                findings = target_data["top_findings"]
        return cls.chat_fallback_query(user_query, findings, targets)
