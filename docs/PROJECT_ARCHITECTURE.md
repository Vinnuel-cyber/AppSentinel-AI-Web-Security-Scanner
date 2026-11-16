# AppSentinel — Project Architecture Specification (v10.0-Final)

## 1. Executive System Overview

AppSentinel is an enterprise-grade, modular web application security scanning and risk assessment platform built on Python 3.11+, Flask, SQLAlchemy, MySQL, and ReportLab. It is engineered to perform authorized reconnaissance, evidence-based vulnerability scanning, automated OWASP Top 10 (2025/2021) classification, FIRST CVSS v4.0 vector scoring, operational risk prioritization, AI-assisted security analysis (with 100% deterministic offline fallback), and cryptographic PDF reporting.

---

## 2. Architectural Blueprint

```
+---------------------------------------------------------------------------------------+
|                                    PRESENTATION LAYER                                 |
|   Bootstrap 5 Dark Cyber SOC Theme | Chart.js Data Visualizations | Jinja2 Templates  |
|   Navbar: Dashboard | Targets | Recon | Scanner | Findings | OWASP | AI Analyst | Reports|
+---------------------------------------------------------------------------------------+
                                           │
                                           ▼ (HTTPS / Session Cookie / CSRF Token)
+---------------------------------------------------------------------------------------+
|                                  APPLICATION & API ROUTING                            |
|  Flask Application Factory | Flask-Login Authentication | Flask-WTF CSRF Protection   |
|                                                                                       |
|  - auth_bp      : User lifecycle, scrypt hashing, brute-force rate limiter            |
|  - dashboard_bp : Real-time SOC metrics, target/scan telemetry, Chart.js feeds        |
|  - targets_bp   : Ownership verification (DNS TXT / HTTP token), SSRF target validator|
|  - recon_bp     : Passive DNS, HTTP headers, endpoint & tech stack discovery          |
|  - scanner_bp   : Active vulnerability orchestration, findings hub, cancellation      |
|  - owasp_bp     : Multi-version taxonomy mapping (2025 default, 2021 historical)      |
|  - risk_bp      : CVSS v4.0 canonical scoring, MacroVector evaluation, P1-P5 triage   |
|  - ai_bp        : Root-cause diagnostics, target posture, contextual chat console     |
|  - reports_bp   : ReportLab PDF generation, SHA-256 integrity, safe downloads         |
+---------------------------------------------------------------------------------------+
                                           │
                    ┌──────────────────────┴──────────────────────┐
                    ▼                                             ▼
+--------------------------------------+      +-----------------------------------------+
|        SCANNING & RECON ENGINES      |      |          SECURITY & RISK ENGINES        |
|  - TargetValidator (SSRF Defense)    |      |  - OWASPMapper (2025/2021 Mappings)     |
|  - ReconEngine & TechDetector        |      |  - CVSS4RiskEngine (FIRST v4.0 Metric)  |
|  - SQLiScanner (Syntax Verification) |      |  - RiskPrioritizer (P1 - P5 Matrix)     |
|  - XSSScanner (Benign DOM Marker)    |      |  - FindingCorrelator (Attack Paths)     |
|  - CookieScanner (Security Flags)    |      |  - RemediationEngine (Defensive Code)   |
|  - MisconfigurationScanner (Headers) |      +-----------------------------------------+
|  - SensitiveDataScanner (Redaction)  |                                  │
|  - InformationDisclosureScanner      |                                  ▼
+--------------------------------------+      +-----------------------------------------+
                    │                         |          AI SECURITY ANALYST            |
                    │                         |  - AIService (Orchestrator)             |
                    │                         |  - ContextBuilder (Tenant-Safe Slicing) |
                    │                         |  - SecretRedactor (Regex Sanitizer)     |
                    │                         |  - PromptManager (Strict Formatting)    |
                    │                         |  - DeterministicFallback (100% Offline) |
                    │                         +-----------------------------------------+
                    │                                                     │
                    ▼                                                     ▼
+---------------------------------------------------------------------------------------+
|                                  PERSISTENCE LAYER (ORM)                              |
|  SQLAlchemy 2.0 | MySQL 8.0+ / SQLite Engine | Strict Foreign Key Constraints         |
|  Users | Targets | Scans | Vulnerabilities | Evidences | OWASPMappings | Reports      |
+---------------------------------------------------------------------------------------+
```

---

## 3. Core Component Modules

### 3.1. Target Ownership & SSRF Defense (`app/security/target_validator.py`)
- **Strict URL Normalization**: Enforces `http` and `https` schemes, strips credentials (`user:pass@`), validates port boundaries (1–65535), and normalizes hosts.
- **SSRF Hardening**: Resolves DNS hostnames and verifies destination IP addresses against IPv4/IPv6 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), multicast, and cloud metadata IPs (`169.254.169.254`).
- **Cryptographic Ownership Verification**: Supports two non-bypassable proof mechanisms:
  - **DNS TXT Record**: Verification query looking for `appsentinel-challenge=<32-byte-token>`.
  - **HTTP Well-Known**: Safe HTTP request fetching `/.well-known/appsentinel-verification.txt`. Re-validates destination IP before connection to prevent DNS rebinding.

### 3.2. Vulnerability Scanning Engine (`app/scanner/`)
- **Non-Destructive Methodology**: Probes targets using safe, non-destructive payloads.
- **Evidence-Based Reporting**: Every finding requires confirmed evidence:
  - `SQLiScanner`: Evaluates database syntax error signatures and differential HTTP behavior.
  - `XSSScanner`: Tests reflection of benign alphanumeric tokens with exact DOM boundary analysis.
  - `CookieScanner`: Evaluates missing `Secure`, `HttpOnly`, and `SameSite` attributes on sensitive session cookies.
  - `SecurityHeaders`: Checks for missing or misconfigured `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, and `X-Frame-Options`.
  - `SensitiveDataScanner`: Scans responses for leaked API keys, tokens, and credentials with immediate auto-redaction before storage.
  - `InformationDisclosureScanner`: Detects exposed stack traces, runtime versions, and system paths.

### 3.3. OWASP Taxonomy & CVSS v4.0 Risk Engine (`app/security/`)
- **Dual Framework Support**: Defaults to **OWASP Top 10:2025** while fully maintaining backwards compatibility with **OWASP Top 10:2021**. Assessments preserve historical framework versions without silent conversion.
- **CWE Taxonomy Integration**: Maps findings to standard Common Weakness Enumeration identifiers (e.g., CWE-89, CWE-79, CWE-693).
- **FIRST CVSS v4.0 Specification**:
  - Implements canonical CVSS v4.0 vector strings (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`).
  - Evaluates MacroVectors (EQ1–EQ6) and calculates deterministic base scores (0.0 to 10.0).
  - Preserves case sensitivity for FIRST metrics (e.g., Provider Urgency: `Clear`, `Green`, `Amber`, `Red`).
- **Operational Risk Prioritizer**: Produces contextual priority levels (`P1` to `P5`) by evaluating CVSS score, environmental exposure, finding confidence, and multi-endpoint recurrence.

### 3.4. AI Security Analyst Subsystem (`app/ai/`)
- **Dual Operating Modes**:
  - **Live Online Mode**: Interacts with the OpenAI API using structured prompt templates and response validation.
  - **Deterministic Offline Fallback Mode**: When `AI_ENABLED=false` or no API key is set, the built-in deterministic engine provides rule-based root cause analysis, risk impact statements, and verified remediation code.
- **Context Builder & Data Isolation**: Validates tenant ownership of findings and targets before assembling prompt contexts. Never includes credentials or cross-tenant data.
- **Multi-Tier Secret Redaction**: Sanitizes text against regular expressions for AWS keys, private RSA/EC keys, bearer tokens, passwords, cookies, and OpenAI API keys before transmission or persistence.

### 3.5. Professional PDF Reporting Subsystem (`app/reports/`)
- **ReportLab Canvas Architecture**: Generates pixel-perfect, branded security assessment reports across three document types:
  - **COMPLETE**: Comprehensive executive summary, target scope, methodology, full vulnerability inventory with evidence snippets, OWASP mapping, and remediation.
  - **VULN_DETAIL**: In-depth technical breakdown of every finding with CVSS v4 vectors, evidence, and remediation code.
  - **EXECUTIVE**: High-level posture analysis, severity distribution charts, risk metrics, and strategic recommendations for leadership.
- **Path Traversal Protection**: Uses strict `Path.resolve()` and `Path.relative_to()` boundary enforcement against `REPORT_FOLDER`.
- **Cryptographic Hash Verification**: Calculates SHA-256 at creation and validates disk file integrity prior to every download. Missing or tampered files are blocked with HTTP 404/500 errors.

---

## 4. Database Schema and Entity Model

```
 ┌──────────────┐         1:N         ┌──────────────┐
 │    User      │ ─────────────────── │    Target    │
 │ (id, role)   │                     │ (owner_id)   │
 └──────────────┘                     └──────────────┘
        │ 1:N                                │ 1:N
        │                                    ▼
        │                             ┌──────────────┐
        │                             │     Scan     │
        │                             │ (target_id)  │
        │                             └──────────────┘
        │                                    │ 1:N
        │                                    ▼
        │                             ┌───────────────────┐
        │                             │   Vulnerability   │
        │                             │ (scan_id, target) │
        │                             └───────────────────┘
        │                                    │ 1:N
        │                                    ├──────────────────────────┐
        │                                    ▼                          ▼
        │                             ┌─────────────────────┐   ┌──────────────┐
        │                             │VulnerabilityEvidence│   │  AIAnalysis  │
        │                             │(vulnerability_id)   │   │ (finding_id) │
        │                             └─────────────────────┘   └──────────────┘
        ▼ 1:N                                                           │
 ┌──────────────┐                                                       │
 │    Report    │ ──────────────────────────────────────────────────────┘
 │ (user_id)    │
 └──────────────┘
```

---

## 5. Security & Isolation Controls Matrix

| Control Category | Implementation Mechanism | Threat Mitigated |
| :--- | :--- | :--- |
| **Authentication** | Password hashing via `scrypt` with random salts | Credential stuffing, rainbow tables |
| **Brute-Force Defense** | IP + User composite rate limiting on `/auth/login` | Online password brute-forcing |
| **Authorization / RBAC** | Role enforcement (`ADMIN`, `USER`) + tenant ownership checks | Privilege escalation, administrative bypass |
| **Tenant Isolation (IDOR)** | Scoped queries filtering by `current_user.id` or verified target ownership | Insecure Direct Object Reference |
| **SSRF Prevention** | DNS resolution validation + Private/Loopback/Metadata IP blocking | Server-Side Request Forgery |
| **Target Verification** | Non-bypassable DNS TXT / HTTP token verification required before scanning | Unauthorized scanning of external assets |
| **CSRF Defense** | Flask-WTF CSRF tokens validated on all mutating HTTP methods | Cross-Site Request Forgery |
| **Data Redaction** | Regex-based sanitization of secrets in evidence, AI prompts, and reports | Accidental credential leakage in reports/logs |
| **Path Traversal Defense** | `pathlib.Path.resolve().relative_to(REPORT_DIR)` check | Arbitrary file read / PDF path traversal |
| **Report Integrity** | Cryptographic SHA-256 calculation and pre-download verification | Report tampering, unauthorized replacement |
| **ReportLab Injection** | XML/HTML escaping of all untrusted evidence text before canvas render | PDF rendering crashes, format corruption |
