class RiskPrioritizer:
    """Enterprise Operational Risk Prioritization Service.
    
    Assigns actionable operational priority tiers (P1 to P5) considering:
    - Independent CVSS v4.0 base score
    - Detection confidence (CONFIRMED vs MEDIUM vs LOW)
    - Target environment (Production vs Staging vs Development)
    - Vulnerability category impact
    - Frequency of repetition across endpoints
    
    Strict principle: Never alters or inflates the official CVSS score.
    Operational triage priority and CVSS severity remain strictly separate.
    """

    PRIORITY_LEVELS = {
        "P1": "Critical Attention (Immediate Remediation Required)",
        "P2": "High Priority (Remediate in Current Sprint)",
        "P3": "Medium Priority (Remediate in Next Release)",
        "P4": "Low Priority (Backlog / Routine Hardening)",
        "P5": "Informational (Defensive Observation)",
    }

    @classmethod
    def determine_priority(
        cls,
        cvss_score: float,
        severity: str,
        confidence: str = "MEDIUM",
        environment: str = "Production",
        repeat_count: int = 1,
        vulnerability_name: str = "",
    ) -> tuple[str, str]:
        """Determine operational priority level (P1-P5) and rationale."""
        conf_upper = (confidence or "MEDIUM").upper()
        env_upper = (environment or "Production").upper()
        sev_upper = (severity or "Medium").upper()
        name_lower = vulnerability_name.lower()

        reasons = []

        # P1 Conditions:
        # 1. Critical CVSS (>= 9.0) with HIGH/CONFIRMED confidence
        # 2. Production SQL Injection or Cryptographic Private Key leak
        if (cvss_score >= 9.0 and conf_upper in ("CONFIRMED", "HIGH")) or (
            "sql injection" in name_lower and conf_upper == "CONFIRMED"
        ) or (
            "private key" in name_lower and conf_upper in ("CONFIRMED", "HIGH")
        ):
            priority = "P1"
            reasons.append(f"CVSS v4.0 score of {cvss_score} ({sev_upper})")
            reasons.append(f"High detection confidence ({conf_upper})")
            if env_upper == "PRODUCTION":
                reasons.append("Deployed in active Production environment")
            if repeat_count > 1:
                reasons.append(f"Detected across {repeat_count} target endpoints")
            explanation = "P1 Critical Attention: " + "; ".join(reasons) + "."
            return priority, explanation

        # P2 Conditions:
        # High CVSS (7.0 - 8.9) OR confirmed Reflected XSS / Session Token issue
        if cvss_score >= 7.0 or (
            sev_upper == "HIGH" and conf_upper in ("CONFIRMED", "HIGH")
        ) or (
            "cross-site scripting" in name_lower and conf_upper == "CONFIRMED"
        ):
            priority = "P2"
            reasons.append(f"CVSS v4.0 score of {cvss_score} ({sev_upper})")
            reasons.append(f"Confidence rating: {conf_upper}")
            if env_upper == "PRODUCTION":
                reasons.append(f"Target is {env_upper}")
            explanation = "P2 High Priority: " + "; ".join(reasons) + "."
            return priority, explanation

        # P3 Conditions:
        # Medium CVSS (4.0 - 6.9) (e.g. Insecure Cookies, Directory Listing, Dangerous Verbs)
        if cvss_score >= 4.0 or sev_upper == "MEDIUM":
            priority = "P3"
            reasons.append(f"CVSS v4.0 score of {cvss_score} ({sev_upper})")
            reasons.append("Significant defense-in-depth weakness requiring scheduled remediation")
            if repeat_count > 2:
                reasons.append(f"Systemic flaw observed across {repeat_count} endpoints")
            explanation = "P3 Medium Priority: " + "; ".join(reasons) + "."
            return priority, explanation

        # P4 Conditions:
        # Low CVSS (0.1 - 3.9) (e.g. Missing headers, banner version disclosure, internal paths)
        if cvss_score > 0.0 or sev_upper == "LOW":
            priority = "P4"
            reasons.append(f"CVSS v4.0 score of {cvss_score} ({sev_upper})")
            reasons.append("Low severity hardening item suitable for routine maintenance")
            explanation = "P4 Low Priority: " + "; ".join(reasons) + "."
            return priority, explanation

        # P5 Conditions:
        # Informational / None
        priority = "P5"
        explanation = "P5 Informational: Defensive baseline observation without direct exploitation path."
        return priority, explanation
