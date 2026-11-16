# Operational Risk Prioritization Framework

This document outlines AppSentinel's operational triage methodology implemented in `app/security/risk_prioritizer.py`. It explains the priority tiers (P1 to P5), the contextual decision matrix, and the explicit separation between mathematical CVSS v4.0 scores, nomenclature designations, and operational actionability.

---

## 1. Motivation: Why CVSS Alone Is Insufficient

CVSS provides an objective, standardized measure of a vulnerability's theoretical technical severity. However, raw CVSS scores do not account for operational realities:
- An unconfirmed heuristic probe on an internal development sandbox does not warrant waking up an engineer at 2:00 AM, even if the theoretical flaw is SQL injection (CVSS 9.3).
- Conversely, a medium-severity reflected XSS (CVSS 5.3) on a production banking portal with co-located missing CSP and unflagged session cookies presents an imminent compound threat.

AppSentinel bridges this gap by calculating two complementary ratings:
1. **CVSS v4.0 Score, Vector & Nomenclature**: The objective technical benchmark (`CVSS-B`, `CVSS-BT`, `CVSS-BE`, `CVSS-BTE`).
2. **Operational Risk Priority (P1–P5)**: The actionable triage queue level.

---

## 2. Priority Levels & SLA Recommendations

| Priority Level | Classification | Response Urgency | Recommended Remediation SLA | Representative Findings |
|---|---|---|---|---|
| **P1** | **Critical / Urgent** | Immediate incident response | **Within 24–48 Hours** | Confirmed SQL Injection in Production, Exposed Cloud/DB Root Secrets, RCE. |
| **P2** | **High / Immediate** | Active priority sprint | **Within 7 Calendar Days** | Confirmed Reflected XSS, Session Cookies Missing `HttpOnly`+`Secure`, Open Directory Listing exposing source code. |
| **P3** | **Medium / Normal** | Standard release cycle | **Within 30 Calendar Days** | Missing `Content-Security-Policy` or `Strict-Transport-Security`, Dangerous HTTP Methods on non-critical endpoints. |
| **P4** | **Low / Deferred** | Maintenance backlog | **Within 60–90 Calendar Days** | Server banner version disclosure, Missing `X-Content-Type-Options`, Heuristic unverified findings. |
| **P5** | **Informational / Hygiene** | Architectural guidance | **Discretionary / Best Practice** | Diagnostic headers, technology fingerprinting, general hardening notices. |

---

## 3. Prioritization Decision Matrix

The prioritization algorithm factors in four primary contextual signals:

### 3.1 Base Severity & Exploitability
- Starting baseline derived from CVSS v4.0 score:
  - Score $\ge 9.0 \rightarrow$ Baseline P1
  - Score $7.0 - 8.9 \rightarrow$ Baseline P2
  - Score $4.0 - 6.9 \rightarrow$ Baseline P3
  - Score $0.1 - 3.9 \rightarrow$ Baseline P4
  - Score $0.0 \rightarrow$ Baseline P5

### 3.2 Target Environment Weighting
- **Production (`PRODUCTION`)**: Highest exposure risk. Findings with confirmed exploitability retain their high priority.
- **Staging / Testing (`STAGING`, `TESTING`)**: Intermediate exposure. Unconfirmed findings may be lowered one tier.
- **Development (`DEVELOPMENT`, `LOCAL`)**: Isolated sandbox environment. Findings are downranked by one operational tier unless confirmed critical.

### 3.3 Detection Confidence Modifiers
- **`CONFIRMED` / `HIGH`**: Direct positive evidence of exploitability observed (e.g., database error response returned, reflection payload unescaped). Priority maintained.
- **`MEDIUM`**: Heuristic or signature-based match. High-severity findings may be de-escalated to prevent alert fatigue.
- **`LOW`**: Weak or indirect indicator. Capped at P4 until manually reviewed by a security analyst.

### 3.4 Compound Synergistic Multipliers
When multiple findings target the same endpoint or form compound attack chains (detected via `FindingCorrelator`):
- **Synergistic Escalation**: Reflected XSS coupled with missing CSP and insecure cookies automatically elevates an asset's aggregate risk tier.
- **Systemic Defect Escalation**: The same vulnerability repeated across 3+ endpoints signals a systemic architectural defect, escalating the asset's overall operational urgency.

---

## 4. Score Nomenclature & Supplemental Safety Integration

Per FIRST CVSS v4.0 Specification:
1. **Score Nomenclature Decoupling**: The nomenclature tags (`CVSS-B`, `CVSS-BT`, `CVSS-BE`, `CVSS-BTE`) identify which metric dimensions contributed to the mathematical score. They are stored alongside the vector for regulatory compliance and auditability.
2. **Supplemental Safety Context**: Supplemental Safety `S:P` (Present) or `S:N` (Negligible) provides analyst visibility into physical/human safety implications without contaminating the mathematical Base score calculation.
3. **Modified Safety Escalation**: Where Modified Subsequent System Safety (`MSI:S` or `MSA:S`) is established, the CVSS engine evaluates MacroVector EQ4 at Level 0, elevating environmental technical severity (`CVSS-BE` / `CVSS-BTE`).

---

## 5. Decoupling Principles & Anti-Corruption Rules

To maintain scientific integrity and auditability, AppSentinel strictly enforces:
1. **CVSS Independence**: The CVSS v4.0 mathematical score is strictly calculated from the 11 base metrics, Threat metric `E`, and Environmental metrics (`CR`, `IR`, `AR`, `M*`).
2. **Confidence Separation**: Scanner detection confidence (`CONFIRMED`, `HIGH`, `MEDIUM`, `LOW`) influences only the operational queue priority (P1–P5), never the underlying CVSS numeric score or vector.
3. **Target Environment Separation**: Deployment context (`Production`, `Staging`, `Development`) modifies triage SLAs without corrupting intrinsic vulnerability severity.
4. **No Hidden Multipliers**: All priority adjustments follow the deterministic decision matrix without arbitrary undocumented scaling factors.
