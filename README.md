# AppSentinel — AI-Powered Web Application Security Scanner (v10.0-Final)

AppSentinel is an enterprise-grade, academic and portfolio-quality web application security assessment platform built with Python 3.11+, Flask, SQLAlchemy, MySQL, and ReportLab. It systematically identifies web vulnerabilities, performs reconnaissance, maps findings to the OWASP Top 10 (2025/2021), calculates risk using FIRST CVSS v4.0 principles, provides deterministic and AI-assisted remediation recommendations, and generates publication-grade PDF security assessment reports.

---

## 1. Project Objectives

- **Automated Security Assessment**: Combine passive reconnaissance with strictly scoped, non-destructive active probes (SQLi, XSS, Security Headers, Cookie Flags, TLS/SSL, Sensitive Data Redaction, Information Disclosure).
- **OWASP Top 10 Alignment**: Map every finding to the official OWASP Top 10:2025 standard (with full backward compatibility for OWASP Top 10:2021) and standard CWE identifiers.
- **FIRST CVSS v4.0 Scoring**: Documented, reproducible severity scoring based on official FIRST CVSS v4.0 canonical vectors, MacroVectors (EQ1–EQ6), and operational priority tiers (P1–P5).
- **AI-Assisted Security Guidance**: Contextual root-cause diagnostics, threat impact statements, and verified remediation code with 100% deterministic offline fallback.
- **Defensive Engineering**: Built-in SSRF protection, cryptographic target domain verification, strict input validation, brute-force rate limiting, multi-tenant IDOR defense, and secure credential storage.
- **Cryptographic PDF Deliverables**: Professional ReportLab PDF reports with SHA-256 integrity verification and path traversal containment.

---

## 2. System Architecture

```
USER / BROWSER
      │
      ▼
FRONTEND (Bootstrap 5, Chart.js, Dark SOC Cyber Theme)
      │
      ▼
FLASK BACKEND API (RESTful Endpoints, Flask-Login, CSRF)
      │
      ├── Authentication (RBAC: Admin, User, scrypt hashing, brute-force limiter)
      ├── Target Management (Domain ownership verification, SSRF guard)
      └── Scan Manager
             │
             ├── Target Validation & Reconnaissance
             ├── Vulnerability Scanner (SQLi, XSS, Headers, Cookies, Sensitive Data)
             ├── Findings & Evidence Engine
             ├── Risk Engine (FIRST CVSS v4.0 Canonical Vectors)
             ├── OWASP Top 10 Analyzer (2025 default & 2021 historical)
             ├── AI Security Analyst (OpenAI Live API / 100% Offline Deterministic Fallback)
             └── Report Generator (ReportLab PDF with SHA-256 Integrity Verification)
                      │
                      ▼
               DATABASE (MySQL 8.0+ / SQLite ORM Models)
```

---

## 3. Technology Stack

- **Backend Runtime**: Python 3.11+
- **Web Framework**: Flask 3.0+, Flask-SQLAlchemy, Flask-Login, Flask-WTF
- **Database**: MySQL 8.0+ / SQLite, SQLAlchemy 2.0 ORM, PyMySQL
- **Security & Inspection**: Cryptography, Requests, BeautifulSoup4
- **Reporting**: ReportLab 4.x / 5.x
- **AI Integration**: OpenAI API (optional, with deterministic offline fallback)
- **Testing**: Pytest, Pytest-Flask (253 automated tests)

---

## 4. Documentation

Comprehensive technical documentation is available in the `docs/` directory:

- [Project Architecture Specification](docs/PROJECT_ARCHITECTURE.md) — Architectural diagrams, data flows, components, and security models.
- [Installation & Deployment Guide](docs/INSTALLATION_GUIDE.md) — Step-by-step setup for virtual environments, MySQL, SQLite, and Flask CLI.
- [User Guide & Operator Manual](docs/USER_GUIDE.md) — Complete manual for registration, verification, scanning, AI diagnostics, and reporting.
- [Final Security Review & Audit](docs/FINAL_SECURITY_REVIEW.md) — Independent security audit covering SSRF, IDOR, prompt injection, and cryptographic integrity.
- [OWASP Mapping Methodology](docs/OWASP_MAPPING.md) — Version-aware taxonomy mapping for OWASP 2025 and 2021 standards.
- [CVSS v4.0 Risk Engine Specification](docs/CVSS_V4_RISK_ENGINE.md) — FIRST CVSS v4.0 specification, MacroVectors, and scoring bands.
- [Risk Prioritization Guide](docs/RISK_PRIORITIZATION.md) — Operational priority (P1–P5) decision matrix and SLA guidelines.
- [Remediation Guide](docs/REMEDIATION_GUIDE.md) — Secure code patterns and remediation verification procedures.
- [PDF Report Generator Specification](docs/PDF_REPORT_GENERATOR.md) — Canvas architecture, report schemas, and design guidelines.
- [Report Security & Integrity Guide](docs/REPORT_SECURITY.md) — Path traversal defense, SHA-256 hashing, and markup escaping.

---

## 5. Project Folder Structure

```
AppSentinel/
├── app.py                     # Application entry point
├── config.py                  # Environment-driven configuration profiles
├── requirements.txt           # Python dependency specifications
├── pytest.ini                 # Pytest test discovery configuration
├── .env.example               # Environment variable template
├── .gitignore                 # Version control exclusion rules
├── README.md                  # Comprehensive documentation
│
├── docs/                      # Technical documentation
│   ├── PROJECT_ARCHITECTURE.md# Complete system architecture specification
│   ├── INSTALLATION_GUIDE.md  # Fresh setup, database & environment guide
│   ├── USER_GUIDE.md          # User manual and operator walkthrough
│   ├── FINAL_SECURITY_REVIEW.md# Comprehensive security controls audit
│   ├── OWASP_MAPPING.md       # OWASP Top 10:2025/2021 mapping methodology
│   ├── CVSS_V4_RISK_ENGINE.md # CVSS v4.0 specification & MacroVectors
│   ├── RISK_PRIORITIZATION.md # Operational priority (P1-P5) decision matrix
│   ├── REMEDIATION_GUIDE.md   # Secure code examples & verification procedures
│   ├── PDF_REPORT_GENERATOR.md# ReportLab engine documentation
│   └── REPORT_SECURITY.md     # PDF security, path containment & integrity
│
├── app/
│   ├── __init__.py            # Application factory (create_app)
│   ├── models/                # SQLAlchemy ORM database models
│   │   ├── __init__.py        # Model registry and db instance
│   │   ├── user.py            # User, roles, password hashing (scrypt)
│   │   ├── target.py          # Targets, domain parsing, verification tokens
│   │   ├── scan.py            # Scans, ScanURL, ScanLog, ScanSetting
│   │   ├── vulnerability.py   # Vulnerability, Evidence, AIAnalysis, Report
│   │   └── owasp.py           # OWASP assessment, CVSS risk, correlation, remediation
│   ├── routes/                # Modular Flask route blueprints
│   │   ├── health.py          # / and /api/health monitoring endpoints
│   │   ├── auth.py            # Authentication & session routes (V2)
│   │   ├── dashboard.py       # Security dashboard routes (V3 & V10)
│   │   ├── targets.py         # Target management & ownership routes (V4)
│   │   ├── recon.py           # Passive reconnaissance routes (V5)
│   │   ├── scanner.py         # Vulnerability scanner engine routes (V6)
│   │   ├── owasp.py           # OWASP Top 10 assessment routes (V7 & V7.1)
│   │   ├── risk.py            # CVSS v4.0 and Risk Engine routes (V7 & V7.2)
│   │   ├── ai.py              # AI Security Analyst routes (V8)
│   │   └── reports.py         # PDF report generation & download routes (V9)
│   ├── scanner/               # Security scanner engines (V5-V6)
│   ├── security/              # SSRF guard, OWASP mapper, CVSS v4 engine, correlator
│   ├── ai/                    # AI analysis & deterministic remediation (V8)
│   ├── reports/               # ReportLab PDF builders, canvas & styling (V9)
│   ├── services/              # Scan orchestration, OWASP services & reporting
│   ├── templates/             # Jinja2 HTML templates (Dark Cyber SOC theme)
│   └── static/                # CSS, JavaScript, and static assets
│
└── tests/                     # Automated test suite (238 passing tests)
    ├── conftest.py            # Pytest fixtures and app factory harness
    ├── test_foundation.py     # Base app, security headers, CLI tests
    ├── test_health.py         # Health-check endpoint tests
    ├── test_models.py         # Database model relationships and validations
    ├── test_auth.py           # Authentication, scrypt, and lockout tests
    ├── test_csrf_session.py   # CSRF protection and session tests
    ├── test_rbac.py           # Role-based access control tests
    ├── test_targets.py        # Target management & audit log tests
    ├── test_target_validation.py # SSRF and URL validation tests
    ├── test_recon.py          # Passive reconnaissance engine tests
    ├── test_vulnerability_scanner.py # Vulnerability scanner tests
    ├── test_owasp_2025_mapper.py # OWASP Top 10:2025 mapping tests
    ├── test_owasp_mapper.py   # OWASP Top 10:2021 backward-compatibility tests
    ├── test_cvss_v4_compliance.py # FIRST CVSS v4.0 compliance tests
    ├── test_cvss_v4_reference_vectors.py # Reference vector tests
    ├── test_historical_owasp_migrations.py # Multi-version migration tests
    ├── test_risk_engine.py    # Risk prioritization tests
    ├── test_finding_correlator.py # Finding correlation tests
    ├── test_remediation_engine.py # Remediation guidance tests
    ├── test_owasp_routes.py   # OWASP & Risk routes tests
    ├── test_ai_config.py      # AI configuration tests
    ├── test_ai_client.py      # AI client & error handling tests
    ├── test_ai_fallback.py    # Deterministic fallback tests
    ├── test_ai_prompt_injection.py # Sanitization & prompt injection tests
    ├── test_ai_response_validator.py # Response validation tests
    ├── test_ai_security_analyst.py # Security analyst service tests
    ├── test_ai_authorization.py # Cross-tenant isolation tests
    ├── test_ai_routes.py      # AI route tests
    ├── test_pdf_reports.py    # ReportLab generation & SHA-256 tests
    └── test_v10_end_to_end_integration.py # Full system integration pipeline
```

---

## 6. Installation & Setup

### Option A: Local Virtual Environment Setup

#### 1. Clone Workspace & Activate Environment
```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

#### 2. Configure Environment & Generate Safe Secrets
Copy `.env.example` to create your local `.env` configuration file:
```powershell
Copy-Item .env.example .env
```
Generate a strong cryptographic secret key and update `SECRET_KEY` in `.env`:
```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```
> [!IMPORTANT]
> The `.env` file contains your local secrets and is strictly ignored by version control (`.gitignore`). Never commit real credentials to GitHub or shared repositories.

#### 3. Initialize Database Schema & Admin
```powershell
flask init-db
flask create-admin --username admin --email admin@appsentinel.local --password "YourStrongAdminPassword123!"
```

#### 4. Run Application
```powershell
python app.py
```
Access the application at [http://127.0.0.1:5000/](http://127.0.0.1:5000/).

---

### Option B: Containerized Deployment via Docker Compose

AppSentinel provides a production-hardened `docker-compose.yml` that isolates the web application and MySQL 8.0 database service.

#### 1. Prepare Environment Secrets
Docker Compose uses environment-variable interpolation with strict required-variable constraints (`${VAR:?error}`). Create `.env` from `.env.example` and supply mandatory production secrets:
```bash
cp .env.example .env
```
Ensure the following required variables are defined in `.env`:
- `SECRET_KEY`: High-entropy session signing key (e.g. generated via `secrets.token_hex(32)`).
- `DB_PASSWORD`: Strong password for the `appsentinel_user` database user.
- `MYSQL_ROOT_PASSWORD`: Dedicated administrative password for MySQL container maintenance.

> [!NOTE]
> By default, the web interface binds to `127.0.0.1:5000` to prevent exposure on external network interfaces. Database health checks evaluate credentials via container environment variables without embedding passwords in YAML.

#### 2. Launch Services
```bash
docker compose up --build -d
```
Docker Compose validates all required secrets before starting services. If any secret is omitted or empty, deployment terminates with an actionable diagnostic.

#### 3. Verify Health & View Logs
```bash
docker compose ps
docker compose logs -f web
```

---

## 7. Running Automated Tests

Run the full automated test suite:
```powershell
pytest -v
```

All **253 tests** execute cleanly with zero failures:
```
====================== 253 passed in ~24s ======================
```

---

## 8. Development Roadmap & Milestone History

- [x] **V1: Project Foundation** — Core architecture, 10 models, configuration, health API, test suite.
- [x] **V2: Authentication & RBAC** — User registration, login, session security, scrypt password hashing, role enforcement.
- [x] **V3: Professional Dark Cyber Dashboard** — Dark SOC UI, metrics cards, Chart.js, statistics.
- [x] **V4: Target Management & Verification** — SSRF validator, DNS TXT & HTTP well-known verification tokens, audit logs.
- [x] **V5: Reconnaissance Engine** — Availability checker, passive tech detector, HTTP auditor, security headers, in-scope crawler, DNS analyzer.
- [x] **V6: Advanced Vulnerability Scanner** — SQLi scanner, XSS scanner, Insecure cookies, Security misconfigurations, Information disclosure, Directory listing, Sensitive data exposure with redaction, Vulnerability Manager.
- [x] **V7: OWASP Analyzer & Risk Engine** — OWASP Top 10:2021 mapping, FIRST CVSS v4.0 scoring engine, operational priority P1-P5, finding correlation & compound threats, deterministic remediation advisories.
- [x] **V7.1: OWASP 2025 Upgrade & CVSS v4.0 Validation** — Dual OWASP 2025/2021 support, FIRST CVSS v4.0 specification audit with EQ1–EQ6 & Threat/Environmental metrics, 14 official reference vectors, historical assessment preservation.
- [x] **V7.2: CVSS v4.0 Compliance Audit** — Strict Base SI/SA metric audit rejecting 'S', MSI/MSA safety support triggering EQ4 Level 0, Supplemental Safety S:P/S:N separation, complete Supplemental metrics AU/R/V/RE/U, 'Not Defined' X preservation and scoring equivalence, duplicate metric rejection, CVSS-B/BT/BE/BTE score nomenclature, canonical vector ordering.
- [x] **V7.2.1: Final CVSS Validation** — Strict case-sensitive Provider Urgency validation rejecting uppercase/lowercase/invalid strings, test count reconciliation across all test suites.
- [x] **V8: AI Security Analyst** — Modular AI Security Analyst architecture, OpenAI Python SDK & Responses API integration, offline deterministic fallback engine, prompt injection defense, structural JSON schema validation, finding root-cause & remediation diagnostics, target posture synthesizer, grounded security chat, cross-user RBAC isolation.
- [x] **V9: Professional PDF Report Generator** — Publication-grade PDF report engine with ReportLab 5.1+, Complete Security Assessment, Vulnerability Detail, and Executive Summary report formats, two-pass NumberedCanvas with "Page X of Y" and running confidentiality headers, CVSS v4.0 & OWASP 2025 matrix, evidence redaction, multi-tenant IDOR download security, path traversal protection, SHA-256 pre-download integrity validation.
- [x] **V10: Final Integration & System Validation** — End-to-end operational pipeline integration, real database metrics telemetry across targets/scans/findings/reports/AI, Chart.js visual telemetry integration, navigation badge alignment (`v10.0-Final`), comprehensive end-to-end integration test suite, complete documentation package (`PROJECT_ARCHITECTURE.md`, `INSTALLATION_GUIDE.md`, `USER_GUIDE.md`, `FINAL_SECURITY_REVIEW.md`), 238 passing tests with 0 failures, 100% offline functionality.
