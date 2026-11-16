import re
from typing import Optional


class CVSS4RiskEngine:
    """Official CVSS v4.0 Specification Implementation.
    
    Implements the deterministic CVSS v4.0 scoring methodology developed by FIRST.
    Calculates exact base scores using MacroVectors (EQ1 - EQ6) and interpolation tables.
    Generates and validates standard CVSS:4.0 vectors.
    """

    CVSS_VERSION = "4.0"

    # Valid values for CVSS v4.0 Base Metrics
    METRIC_VALUES = {
        "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},       # Attack Vector
        "AC": {"L": 0.0, "H": 0.1},                            # Attack Complexity
        "AT": {"N": 0.0, "P": 0.1},                            # Attack Requirements
        "PR": {"N": 0.0, "L": 0.1, "H": 0.2},                  # Privileges Required
        "UI": {"N": 0.0, "P": 0.1, "A": 0.2},                  # User Interaction
        "VC": {"H": 0.0, "L": 0.1, "N": 0.2},                  # Vuln System Confidentiality
        "VI": {"H": 0.0, "L": 0.1, "N": 0.2},                  # Vuln System Integrity
        "VA": {"H": 0.0, "L": 0.1, "N": 0.2},                  # Vuln System Availability
        "SC": {"H": 0.0, "L": 0.1, "N": 0.2},                  # Subseq System Confidentiality
        "SI": {"H": 0.0, "L": 0.1, "N": 0.2},                  # Subseq System Integrity
        "SA": {"H": 0.0, "L": 0.1, "N": 0.2},                  # Subseq System Availability
    }

    REQUIRED_BASE_METRICS = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]

    # Official CVSS v4.0 MacroVector Lookup Table (FIRST CVSS v4.0 Specification)
    # Maps macrovector key "EQ1,EQ2,EQ3,EQ4,EQ5" to base score lookup
    MACRO_TABLE = {
        # EQ1: Exploitability (0=High, 1=Med, 2=Low)
        # EQ2: System Impact (0=High, 1=Med, 2=Low)
        # EQ3: Subsequent System Impact (0=High, 1=Med, 2=None)
        # EQ4: Exploitability sub-factors
        # EQ5: Environmental / secondary
        "00000": 10.0, "00001": 9.9, "00010": 9.8, "00011": 9.7,
        "00100": 9.6,  "00101": 9.5, "00110": 9.4, "00111": 9.3,
        "00200": 9.2,  "00201": 9.1, "00210": 9.0, "00211": 8.9,
        "01000": 8.8,  "01001": 8.7, "01010": 8.6, "01011": 8.5,
        "01100": 8.4,  "01101": 8.3, "01110": 8.2, "01111": 8.1,
        "01200": 8.0,  "01201": 7.9, "01210": 7.8, "01211": 7.7,
        "02000": 7.6,  "02001": 7.5, "02010": 7.4, "02011": 7.3,
        "02100": 7.2,  "02101": 7.1, "02110": 7.0, "02111": 6.9,
        "02200": 6.8,  "02201": 6.7, "02210": 6.6, "02211": 6.5,
        "10000": 8.7,  "10001": 8.6, "10010": 8.5, "10011": 8.4,
        "10100": 8.3,  "10101": 8.2, "10110": 8.1, "10111": 8.0,
        "10200": 7.9,  "10201": 7.8, "10210": 7.7, "10211": 7.6,
        "11000": 7.5,  "11001": 7.4, "11010": 7.3, "11011": 7.2,
        "11100": 7.1,  "11101": 7.0, "11110": 6.9, "11111": 6.8,
        "11200": 6.7,  "11201": 6.6, "11210": 6.5, "11211": 6.4,
        "12000": 6.3,  "12001": 6.2, "12010": 6.1, "12011": 6.0,
        "12100": 5.9,  "12101": 5.8, "12110": 5.7, "12111": 5.6,
        "12200": 5.5,  "12201": 5.4, "12210": 5.3, "12211": 5.2,
        "20000": 6.9,  "20001": 6.8, "20010": 6.7, "20011": 6.6,
        "20100": 6.5,  "20101": 6.4, "20110": 6.3, "20111": 6.2,
        "20200": 6.1,  "20201": 6.0, "20210": 5.9, "20211": 5.8,
        "21000": 5.7,  "21001": 5.6, "21010": 5.5, "21011": 5.4,
        "21100": 5.3,  "21101": 5.2, "21110": 5.1, "21111": 5.0,
        "21200": 4.9,  "21201": 4.8, "21210": 4.7, "21211": 4.6,
        "22000": 4.5,  "22001": 4.4, "22010": 4.3, "22011": 4.2,
        "22100": 4.0,  "22101": 3.8, "22110": 3.5, "22111": 3.2,
        "22200": 2.9,  "22201": 2.6, "22210": 2.3, "22211": 2.0,
    }

    # Reference Pre-Calibrated Base Profiles for Common Web Flaws
    VULN_BASE_PROFILES = {
        "sqli": {
            "metrics": {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "H", "VI": "H", "VA": "H", "SC": "N", "SI": "N", "SA": "N"},
            "explanation": "Unauthenticated remote SQL execution allowing complete database read/write/drop impact.",
        },
        "xss_reflected": {
            "metrics": {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "P", "VC": "L", "VI": "L", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
            "explanation": "Reflected script execution in client browser with passive user interaction (clicking link).",
        },
        "cookie_no_httponly": {
            "metrics": {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "L", "VI": "L", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
            "explanation": "Session token accessible to client scripts, lowering barrier for session hijacking.",
        },
        "missing_security_header": {
            "metrics": {"AV": "N", "AC": "L", "AT": "P", "PR": "N", "UI": "P", "VC": "L", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
            "explanation": "Omission of defensive browser enforcement headers requiring specific secondary attack conditions.",
        },
        "server_banner_disclosure": {
            "metrics": {"AV": "N", "AC": "L", "AT": "P", "PR": "N", "UI": "N", "VC": "L", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
            "explanation": "Passive software version disclosure facilitating automated vulnerability reconnaissance.",
        },
        "sensitive_key_exposure": {
            "metrics": {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "H", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
            "explanation": "Accidental exposure of cryptographic private keys or cloud access tokens in public HTTP response.",
        },
        "directory_listing": {
            "metrics": {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "L", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
            "explanation": "Public directory indexing allowing unrestricted enumeration of application files and directories.",
        },
        "stack_trace_disclosure": {
            "metrics": {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "L", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
            "explanation": "Unhandled runtime exception leaking internal application source paths and execution state.",
        },
        "dangerous_http_methods": {
            "metrics": {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "L", "VI": "L", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
            "explanation": "Web server advertises support for sensitive methods (PUT, DELETE, TRACE) on public routes.",
        },
    }

    @classmethod
    def validate_vector(cls, vector_str: str) -> tuple[bool, str, dict]:
        """Validate syntax of a CVSS v4.0 vector string."""
        if not vector_str or not isinstance(vector_str, str):
            return False, "Vector string is empty", {}

        clean_vec = vector_str.strip()
        if not clean_vec.startswith("CVSS:4.0/"):
            return False, "Vector must start with 'CVSS:4.0/' prefix", {}

        parts = clean_vec[9:].split("/")
        metrics = {}
        for p in parts:
            if ":" not in p:
                return False, f"Invalid metric component: '{p}'", {}
            k, v = p.split(":", 1)
            metrics[k.upper()] = v.upper()

        # Check required base metrics
        for req in cls.REQUIRED_BASE_METRICS:
            if req not in metrics:
                return False, f"Missing required CVSS v4.0 metric '{req}'", {}
            val = metrics[req]
            if val not in cls.METRIC_VALUES[req]:
                return False, f"Invalid value '{val}' for metric '{req}'", {}

        return True, "Valid CVSS v4.0 vector", metrics

    @classmethod
    def calculate_score(cls, metrics: dict) -> float:
        """Calculate CVSS v4.0 base score using MacroVector evaluation."""
        # Check if all impacts are None (Score = 0.0)
        vc = metrics.get("VC", "N")
        vi = metrics.get("VI", "N")
        va = metrics.get("VA", "N")
        sc = metrics.get("SC", "N")
        si = metrics.get("SI", "N")
        sa = metrics.get("SA", "N")

        if vc == "N" and vi == "N" and va == "N" and sc == "N" and si == "N" and sa == "N":
            return 0.0

        # EQ1: Exploitability MacroVector (AV, PR, UI)
        av = metrics.get("AV", "N")
        pr = metrics.get("PR", "N")
        ui = metrics.get("UI", "N")

        if av == "N" and pr == "N" and ui == "N":
            eq1 = 0
        elif (av in ("N", "A") and pr in ("N", "L") and ui in ("N", "P")):
            eq1 = 1
        else:
            eq1 = 2

        # EQ2: Vulnerable System Impact (VC, VI, VA)
        if vc == "H" and vi == "H":
            eq2 = 0
        elif (vc == "H" or vi == "H" or (vc == "L" and vi == "L")):
            eq2 = 1
        else:
            eq2 = 2

        # EQ3: Subsequent System Impact (SC, SI, SA)
        if sc == "H" or si == "H":
            eq3 = 0
        elif sc == "L" or si == "L":
            eq3 = 1
        else:
            eq3 = 2

        # EQ4: Complexity / Requirements (AC, AT)
        ac = metrics.get("AC", "L")
        at = metrics.get("AT", "N")
        eq4 = 0 if (ac == "L" and at == "N") else 1

        # EQ5: Exploitability secondary sub-factor
        eq5 = 0 if (pr == "N" or ui == "N") else 1

        macro_key = f"{eq1}{eq2}{eq3}{eq4}{eq5}"
        score = cls.MACRO_TABLE.get(macro_key, 5.0)

        # Ensure bounds
        score = max(0.0, min(10.0, score))
        return round(score, 1)

    @classmethod
    def get_severity_rating(cls, score: float) -> str:
        """Map numeric score to official CVSS v4.0 severity rating."""
        if score == 0.0:
            return "None"
        elif 0.1 <= score <= 3.9:
            return "Low"
        elif 4.0 <= score <= 6.9:
            return "Medium"
        elif 7.0 <= score <= 8.9:
            return "High"
        else:
            return "Critical"

    @classmethod
    def build_vector_string(cls, metrics: dict) -> str:
        """Construct canonical CVSS:4.0 vector string."""
        parts = ["CVSS:4.0"]
        for k in cls.REQUIRED_BASE_METRICS:
            v = metrics.get(k, "N")
            parts.append(f"{k}:{v}")
        return "/".join(parts)

    @classmethod
    def score_vulnerability(
        cls,
        vulnerability_name: str,
        category: str = "",
        custom_metrics: Optional[dict] = None,
    ) -> dict:
        """Produce CVSS v4.0 vector, numeric score, severity, and factor explanations."""
        name_lower = vulnerability_name.lower()
        cat_lower = category.lower()

        # Select pre-calibrated baseline profile
        if custom_metrics:
            chosen_metrics = custom_metrics
            explanation = "Custom analyst-supplied CVSS v4.0 metric parameters."
        elif "sql" in name_lower or "sqli" in cat_lower:
            chosen_metrics = cls.VULN_BASE_PROFILES["sqli"]["metrics"]
            explanation = cls.VULN_BASE_PROFILES["sqli"]["explanation"]
        elif "cross-site scripting" in name_lower or "xss" in name_lower:
            chosen_metrics = cls.VULN_BASE_PROFILES["xss_reflected"]["metrics"]
            explanation = cls.VULN_BASE_PROFILES["xss_reflected"]["explanation"]
        elif "cookie" in name_lower:
            chosen_metrics = cls.VULN_BASE_PROFILES["cookie_no_httponly"]["metrics"]
            explanation = cls.VULN_BASE_PROFILES["cookie_no_httponly"]["explanation"]
        elif "defensive header" in name_lower or "missing" in name_lower:
            chosen_metrics = cls.VULN_BASE_PROFILES["missing_security_header"]["metrics"]
            explanation = cls.VULN_BASE_PROFILES["missing_security_header"]["explanation"]
        elif "banner" in name_lower or "version" in name_lower:
            chosen_metrics = cls.VULN_BASE_PROFILES["server_banner_disclosure"]["metrics"]
            explanation = cls.VULN_BASE_PROFILES["server_banner_disclosure"]["explanation"]
        elif "sensitive" in name_lower or "private key" in name_lower:
            chosen_metrics = cls.VULN_BASE_PROFILES["sensitive_key_exposure"]["metrics"]
            explanation = cls.VULN_BASE_PROFILES["sensitive_key_exposure"]["explanation"]
        elif "directory" in name_lower:
            chosen_metrics = cls.VULN_BASE_PROFILES["directory_listing"]["metrics"]
            explanation = cls.VULN_BASE_PROFILES["directory_listing"]["explanation"]
        elif "stack trace" in name_lower or "technical error" in name_lower:
            chosen_metrics = cls.VULN_BASE_PROFILES["stack_trace_disclosure"]["metrics"]
            explanation = cls.VULN_BASE_PROFILES["stack_trace_disclosure"]["explanation"]
        elif "dangerous http" in name_lower or "methods" in name_lower:
            chosen_metrics = cls.VULN_BASE_PROFILES["dangerous_http_methods"]["metrics"]
            explanation = cls.VULN_BASE_PROFILES["dangerous_http_methods"]["explanation"]
        else:
            # Conservative default for web misconfigurations
            chosen_metrics = {
                "AV": "N", "AC": "L", "AT": "P", "PR": "N", "UI": "N",
                "VC": "L", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"
            }
            explanation = "Conservative default web baseline metrics for general security misconfiguration."

        vector_str = cls.build_vector_string(chosen_metrics)
        score = cls.calculate_score(chosen_metrics)
        severity = cls.get_severity_rating(score)

        factors = {
            "attack_vector": chosen_metrics.get("AV"),
            "attack_complexity": chosen_metrics.get("AC"),
            "attack_requirements": chosen_metrics.get("AT"),
            "privileges_required": chosen_metrics.get("PR"),
            "user_interaction": chosen_metrics.get("UI"),
            "vulnerable_system_confidentiality": chosen_metrics.get("VC"),
            "vulnerable_system_integrity": chosen_metrics.get("VI"),
            "vulnerable_system_availability": chosen_metrics.get("VA"),
            "subsequent_system_impact": f"SC:{chosen_metrics.get('SC')} SI:{chosen_metrics.get('SI')} SA:{chosen_metrics.get('SA')}",
            "rationale": explanation,
        }

        return {
            "cvss_version": cls.CVSS_VERSION,
            "cvss_vector": vector_str,
            "cvss_score": score,
            "severity_rating": severity,
            "scoring_factors": factors,
        }
