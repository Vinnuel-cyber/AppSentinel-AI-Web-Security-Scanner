# OWASP Top 10 Mapping Methodology & Version-Aware Taxonomy

This document describes the taxonomy, classification rules, confidence scoring, and mapping methodology used by AppSentinel's Version-Aware OWASP Mapping Engine (`app/security/owasp_mapper.py`).

---

## 1. Overview & Dual-Framework Support

AppSentinel provides enterprise-grade, version-aware taxonomy mapping supporting both the latest **OWASP Top 10:2025** standard and the preceding **OWASP Top 10:2021** standard.

### 1.1 Key Principles:
1. **Default Standard**: **OWASP Top 10:2025** is the default standard applied to all newly executed security assessments.
2. **Historical Preservation**: All historical assessments performed under OWASP Top 10:2021 retain their original category classifications, metrics, and report mappings. They are **never** silently converted or mutated.
3. **Explicit Version Tagging**: Every assessment (`OWASPAssessment`) and finding mapping record (`OWASPFindingMapping`) carries an explicit `framework_version` field (`"2025"` or `"2021"`).
4. **Independent Filtering**: The security dashboard provides dedicated filtering to inspect assessments and findings under either framework release or across all historical records.

---

## 2. Category Indices: 2025 vs. 2021

### 2.1 OWASP Top 10:2025 (Official Standard)
Reference: [https://owasp.org/Top10/2025/](https://owasp.org/Top10/2025/)

| Category ID | Category Name | Evolution & Core Focus |
|---|---|---|
| **A01:2025** | Broken Access Control | Remains #1. Directory traversal, directory listing, IDOR, privilege escalation, CORS misconfigurations. |
| **A02:2025** | Security Misconfiguration | Elevated to #2. Insecure defaults, missing defensive HTTP headers, verbose banners, unnecessary services. |
| **A03:2025** | Software Supply Chain Failures | Replaces outdated components. Vulnerable third-party dependencies, CI/CD pipeline integrity, poisoned libraries. |
| **A04:2025** | Cryptographic Failures | Relocated from A02. Insecure key management, cleartext transmission, unmasked API secrets. |
| **A05:2025** | Injection | Relocated from A03. SQL injection, Command injection, Cross-Site Scripting (XSS). |
| **A06:2025** | Insecure Design | Architectural flaws, missing rate limiting, threat modeling gaps. |
| **A07:2025** | Authentication Failures | Formerly Identification & Authentication Failures. Insecure session cookies, credential stuffing, session fixation. |
| **A08:2025** | Software or Data Integrity Failures | Insecure deserialization, unsigned firmware/code execution. |
| **A09:2025** | Security Logging and Alerting Failures | Insufficient audit logging, missing real-time alerting on security incidents. |
| **A10:2025** | Mishandling of Exceptional Conditions | **New Category**. Unhandled runtime exceptions, stack trace disclosures, diagnostic crashes. |

### 2.2 OWASP Top 10:2021 (Historical Standard)
Reference: [https://owasp.org/Top10/](https://owasp.org/Top10/)

| Category ID | Category Name | Description |
|---|---|---|
| **A01:2021** | Broken Access Control | Unauthorized access, missing permissions, directory listing. |
| **A02:2021** | Cryptographic Failures | Cleartext credentials, weak ciphers. |
| **A03:2021** | Injection | SQLi, Command Injection, Reflected XSS. |
| **A04:2021** | Insecure Design | Architecture and design flaws. |
| **A05:2021** | Security Misconfiguration | Missing security headers, error banners, stack traces. |
| **A06:2021** | Vulnerable and Outdated Components | Legacy packages, known CVEs. |
| **A07:2021** | Identification and Authentication Failures | Weak session tokens, cookie flag omissions. |
| **A08:2021** | Software and Data Integrity Failures | Insecure deserialization, CI/CD risks. |
| **A09:2021** | Security Logging and Monitoring Failures | Missing logs, lack of audit trails. |
| **A10:2021** | Server-Side Request Forgery (SSRF) | SSRF exploitation. |

---

## 3. Finding-to-OWASP Mapping Taxonomy

### 3.1 SQL Injection (`SQLI_ERROR_BASED`, `SQLI_BOOLEAN_BASED`, `SQLI_TIME_BASED`)
- **OWASP 2025**:
  - Primary: `A05:2025 - Injection`
  - Secondary: `A02:2025 - Security Misconfiguration`
  - CWE: `CWE-89`
  - Rationale: Untrusted user input interpreted as SQL commands. Detailed DB syntax error leakage secondary under A02:2025.
- **OWASP 2021**:
  - Primary: `A03:2021 - Injection`
  - Secondary: `A05:2021 - Security Misconfiguration`
  - CWE: `CWE-89`
- **Confidence**: `HIGH`

### 3.2 Reflected Cross-Site Scripting (`XSS_REFLECTED`)
- **OWASP 2025**:
  - Primary: `A05:2025 - Injection`
  - Secondary: `A02:2025 - Security Misconfiguration`
  - CWE: `CWE-79`
  - Rationale: Unsanitized client reflection enables arbitrary script execution. Missing CSP secondary under A02:2025.
- **OWASP 2021**:
  - Primary: `A03:2021 - Injection`
  - Secondary: `A05:2021 - Security Misconfiguration`
  - CWE: `CWE-79`
- **Confidence**: `HIGH`

### 3.3 Insecure Session Cookie Attributes (`INSECURE_COOKIE_ATTRIBUTES`)
- **OWASP 2025**:
  - Primary: `A02:2025 - Security Misconfiguration`
  - Secondary: `A07:2025 - Authentication Failures`
  - CWE: `CWE-614`, `CWE-1004`
  - Rationale: Failure to enforce defensive flags (HttpOnly, Secure, SameSite) constitutes security misconfiguration with authentication exposure.
- **OWASP 2021**:
  - Primary: `A05:2021 - Security Misconfiguration`
  - Secondary: `A07:2021 - Identification and Authentication Failures`
  - CWE: `CWE-614`, `CWE-1004`
- **Confidence**: `HIGH`

### 3.4 Missing HTTP Security Headers (`MISSING_SECURITY_HEADERS`)
- **OWASP 2025**:
  - Primary: `A02:2025 - Security Misconfiguration`
  - Secondary: None
  - CWE: `CWE-693`, `CWE-1021`
- **OWASP 2021**:
  - Primary: `A05:2021 - Security Misconfiguration`
  - Secondary: None
  - CWE: `CWE-693`, `CWE-1021`
- **Confidence**: `HIGH`

### 3.5 Diagnostic Stack Trace Leaks (`STACK_TRACE_DISCLOSURE`)
- **OWASP 2025**:
  - Primary: `A10:2025 - Mishandling of Exceptional Conditions`
  - Secondary: `A02:2025 - Security Misconfiguration`
  - CWE: `CWE-209`, `CWE-248`
  - Rationale: Unhandled runtime errors leaking internal file paths and execution traces map directly to the dedicated 2025 exceptional condition handling category.
- **OWASP 2021**:
  - Primary: `A05:2021 - Security Misconfiguration`
  - Secondary: `A04:2021 - Insecure Design`
  - CWE: `CWE-209`
- **Confidence**: `HIGH`

### 3.6 Sensitive Data & Private Key Exposure (`SENSITIVE_DATA_EXPOSURE`)
- **OWASP 2025**:
  - Primary: `A04:2025 - Cryptographic Failures`
  - Secondary: `A01:2025 - Broken Access Control`
  - CWE: `CWE-312`, `CWE-798`
- **OWASP 2021**:
  - Primary: `A02:2021 - Cryptographic Failures`
  - Secondary: `A05:2021 - Security Misconfiguration`
  - CWE: `CWE-312`, `CWE-798`
- **Confidence**: `HIGH`

### 3.7 Open Directory Listing (`DIRECTORY_LISTING`)
- **OWASP 2025**:
  - Primary: `A01:2025 - Broken Access Control`
  - Secondary: `A02:2025 - Security Misconfiguration`
  - CWE: `CWE-548`
- **OWASP 2021**:
  - Primary: `A01:2021 - Broken Access Control`
  - Secondary: `A05:2021 - Security Misconfiguration`
  - CWE: `CWE-548`
- **Confidence**: `HIGH`

### 3.8 Server Software Version & Banner Disclosure (`SERVER_BANNER_DISCLOSURE`)
- **OWASP 2025**:
  - Primary: `A02:2025 - Security Misconfiguration`
  - Secondary: `A01:2025 - Broken Access Control`
  - CWE: `CWE-200`
- **OWASP 2021**:
  - Primary: `A05:2021 - Security Misconfiguration`
  - Secondary: `A01:2021 - Broken Access Control`
  - CWE: `CWE-200`
- **Confidence**: `HIGH`

---

## 4. Confidence Evaluation Rules

- **`HIGH` Confidence**: Direct, empirical scanner confirmation (e.g. database syntax exception returned, payload reflected verbatim without escaping, private key block matched).
- **`MEDIUM` Confidence**: Reliable heuristic signature or method probe (e.g. OPTIONS HTTP response returning PUT/DELETE).
- **`LOW` Confidence**: Heuristic, generic, or ambiguous finding lacking clear technical markers. Conservatively mapped to general Security Misconfiguration (`A02:2025` or `A05:2021`) pending security analyst triage.
