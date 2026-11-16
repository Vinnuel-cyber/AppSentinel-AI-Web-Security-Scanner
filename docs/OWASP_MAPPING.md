# OWASP Top 10:2021 Mapping Methodology & Taxonomy

This document describes the taxonomy, classification rules, confidence scoring, and mapping methodology used by AppSentinel's OWASP Mapping Engine (`app/security/owasp_mapper.py`).

---

## 1. Overview & Standard Alignment

AppSentinel aligns all vulnerability findings to the official **OWASP Top 10:2021** application security standard. Every finding detected by the automated scanner is classified with:
- **Primary OWASP Category**: The fundamental architectural or implementation weakness.
- **Secondary OWASP Category**: An associated contributing or co-occurring category when applicable.
- **CWE Cross-Reference**: Official Common Weakness Enumeration identifier(s).
- **Mapping Confidence**: Confidence level (`HIGH`, `MEDIUM`, `LOW`) with a detailed technical rationale.

---

## 2. OWASP Top 10:2021 Category Index

| Category ID | Category Name | Description & Core Focus |
|---|---|---|
| **A01:2021** | Broken Access Control | Unauthorized access, missing authorization checks, directory traversal, directory listing, CORS misconfiguration, and privilege escalation. |
| **A02:2021** | Cryptographic Failures | Exposure of sensitive credentials, weak cryptography, plaintext transmission of secrets, API key exposure, and missing TLS encryption. |
| **A03:2021** | Injection | SQL injection, NoSQL injection, OS command injection, Cross-Site Scripting (XSS), and untrusted data interpreted as commands or code. |
| **A04:2021** | Insecure Design | Architectural flaws, missing rate limiting, business logic bypasses, and threat modeling gaps. |
| **A05:2021** | Security Misconfiguration | Insecure default configurations, missing HTTP security headers (CSP, HSTS, X-Frame-Options), verbose error banners, default credentials, and debug endpoints. |
| **A06:2021** | Vulnerable and Outdated Components | Deprecated libraries, outdated CMS/server versions, known CVEs in third-party packages. |
| **A07:2021** | Identification and Authentication Failures | Weak session management, missing `HttpOnly` or `Secure` flags on session cookies, brute-force vulnerability, and credential stuffing. |
| **A08:2021** | Software and Data Integrity Failures | Insecure deserialization, untrusted CI/CD pipelines, missing integrity checks on code or critical updates. |
| **A09:2021** | Security Logging and Monitoring Failures | Insufficient logging, lack of real-time audit trails, missing tamper-resistant logs. |
| **A10:2021** | Server-Side Request Forgery (SSRF) | Flaws allowing unauthenticated servers to initiate requests to internal, loopback, or metadata services. |

---

## 3. Detailed Finding-to-OWASP Mapping Rules

### 3.1 SQL Injection (`SQLI_ERROR_BASED`, `SQLI_BOOLEAN_BASED`, `SQLI_TIME_BASED`)
- **Primary OWASP**: `A03:2021 - Injection`
- **Secondary OWASP**: `A05:2021 - Security Misconfiguration` (when detailed database engine errors are revealed in responses)
- **Primary CWE**: `CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')`
- **Secondary CWE**: `CWE-209: Generation of Error Message Containing Sensitive Information`
- **Rationale**: SQL syntax probes triggered backend database interpreter execution errors, demonstrating untrusted input concatenation directly into dynamic SQL queries without parameterized binding.
- **Mapping Confidence**: `HIGH`

### 3.2 Reflected Cross-Site Scripting (`XSS_REFLECTED`)
- **Primary OWASP**: `A03:2021 - Injection`
- **Secondary OWASP**: `A05:2021 - Security Misconfiguration` (lack of Content-Security-Policy enables trivial script execution)
- **Primary CWE**: `CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')`
- **Secondary CWE**: `CWE-116: Improper Encoding or Escaping of Output`
- **Rationale**: Unsanitized user-supplied payload was reflected verbatim in the HTTP response DOM with executable context, allowing arbitrary client-side script execution in victims' browsers.
- **Mapping Confidence**: `HIGH`

### 3.3 Insecure Session Cookies (`INSECURE_COOKIE_ATTRIBUTES`)
- **Primary OWASP**: `A05:2021 - Security Misconfiguration`
- **Secondary OWASP**: `A07:2021 - Identification and Authentication Failures`
- **Primary CWE**: `CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute`
- **Secondary CWE**: `CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag`, `CWE-1275: Sensitive Cookie with Improper SameSite Attribute`
- **Rationale**: HTTP response sets session or authentication tokens without strict defensive security flags (`Secure`, `HttpOnly`, `SameSite=Strict/Lax`), exposing session tokens to network sniffing and cross-site script theft.
- **Mapping Confidence**: `HIGH`

### 3.4 Missing Security Headers (`MISSING_SECURITY_HEADERS`)
- **Primary OWASP**: `A05:2021 - Security Misconfiguration`
- **Secondary OWASP**: `None`
- **Primary CWE**: `CWE-1021: Improper Restriction of Rendered UI Layers or Frames`
- **Secondary CWE**: `CWE-319: Cleartext Transmission of Sensitive Information`, `CWE-693: Protection Mechanism Failure`
- **Rationale**: The web server fails to supply standard defensive HTTP response headers (e.g., `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`), weakening browser security enforcement.
- **Mapping Confidence**: `HIGH`

### 3.5 Server Banner & Technology Disclosure (`SERVER_BANNER_DISCLOSURE`)
- **Primary OWASP**: `A05:2021 - Security Misconfiguration`
- **Secondary OWASP**: `A01:2021 - Broken Access Control`
- **Primary CWE**: `CWE-200: Exposure of Sensitive Information to an Unauthorized Actor`
- **Secondary CWE**: `CWE-497: Exposure of Sensitive System Information to an Unauthorized Control Sphere`
- **Rationale**: Server or framework version numbers (e.g., `Server: Apache/2.4.41`, `X-Powered-By: PHP/7.4.3`) are broadcast in response headers, aiding attacker reconnaissance for targeted CVE exploitation.
- **Mapping Confidence**: `HIGH`

### 3.6 Diagnostic Stack Trace Disclosure (`STACK_TRACE_DISCLOSURE`)
- **Primary OWASP**: `A05:2021 - Security Misconfiguration`
- **Secondary OWASP**: `A01:2021 - Broken Access Control`
- **Primary CWE**: `CWE-209: Generation of Error Message Containing Sensitive Information`
- **Secondary CWE**: `CWE-200: Exposure of Sensitive Information to an Unauthorized Actor`
- **Rationale**: Verbose backend debug traces, source file paths, or framework runtime exceptions were returned in response to malformed input, revealing internal application architecture and code structure.
- **Mapping Confidence**: `HIGH`

### 3.7 Enabled Dangerous HTTP Methods (`DANGEROUS_HTTP_METHODS`)
- **Primary OWASP**: `A05:2021 - Security Misconfiguration`
- **Secondary OWASP**: `A01:2021 - Broken Access Control`
- **Primary CWE**: `CWE-749: Exposed Dangerous Method or Function`
- **Secondary CWE**: `CWE-650: Trusting HTTP Permission Methods on the Server Side`
- **Rationale**: The endpoint permits unsafe HTTP methods such as `PUT`, `DELETE`, or `TRACE`, potentially allowing unauthorized file uploads, deletions, or Cross-Site Tracing (XST) attacks.
- **Mapping Confidence**: `MEDIUM`

### 3.8 Open Directory Listing (`DIRECTORY_LISTING`)
- **Primary OWASP**: `A01:2021 - Broken Access Control`
- **Secondary OWASP**: `A05:2021 - Security Misconfiguration`
- **Primary CWE**: `CWE-548: Exposure of Information Through Directory Listing`
- **Secondary CWE**: `CWE-200: Exposure of Sensitive Information to an Unauthorized Actor`
- **Rationale**: Web server index rendering is enabled for directories lacking default index documents, exposing file structures, backup archives, configuration files, and private resources to unauthenticated visitors.
- **Mapping Confidence**: `HIGH`

### 3.9 Sensitive Data & Secrets Exposure (`SENSITIVE_DATA_EXPOSURE`)
- **Primary OWASP**: `A02:2021 - Cryptographic Failures`
- **Secondary OWASP**: `A01:2021 - Broken Access Control`
- **Primary CWE**: `CWE-312: Cleartext Storage of Sensitive Information`
- **Secondary CWE**: `CWE-798: Use of Hard-coded Credentials`, `CWE-200: Exposure of Sensitive Information`
- **Rationale**: Unmasked private API keys, bearer tokens, database connection strings, or cryptographic secrets were detected in client-accessible responses or scripts.
- **Mapping Confidence**: `HIGH`

---

## 4. Assessment Session Aggregation

When an assessment is performed on an authorized target (`app/services/owasp_service.py`), the mapper:
1. Iterates through all confirmed and active findings for the target.
2. Evaluates primary and secondary OWASP mappings.
3. Groups findings into category frequency tables.
4. Identifies the **Top Critical OWASP Category** dominating the target's risk surface.
5. Computes a category distribution breakdown presented on the target's OWASP assessment dashboard.
