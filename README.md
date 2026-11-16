# AppSentinel — AI-Powered Web Application Security Scanner

AppSentinel is an enterprise-grade, academic and portfolio-quality web application security assessment platform. It systematically identifies web vulnerabilities, performs reconnaissance, maps findings to the OWASP Top 10, calculates risk using CVSS v4.0 principles, provides deterministic and AI-assisted remediation recommendations, and generates executive and technical PDF security reports.

---

## 1. Project Objectives

- **Automated Security Assessment**: Combine passive analysis with strictly scoped, non-destructive active probes (SQLi, XSS, Security Headers, Cookie Flags, TLS/SSL, Information Disclosure).
- **OWASP Top 10 Alignment**: Map every finding to the official OWASP Top 10 standard with version-aware taxonomy and CWE identifiers.
- **Risk Prioritization**: Documented, reproducible severity scoring (Critical, High, Medium, Low, Informational) based on CVSS v4.0 metrics.
- **AI-Assisted Guidance**: Contextual remediation, root-cause analysis, and secure coding patterns with deterministic fallbacks when AI APIs are unavailable.
- **Defensive Engineering**: Built-in SSRF protection, target domain verification, strict input validation, rate limiting, and secure credential storage.

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
      ├── Authentication (RBAC: Admin, Analyst, User)
      ├── Target Management (Domain ownership verification, SSRF guard)
      └── Scan Manager
             │
             ├── Target Validation & Reconnaissance
             ├── Vulnerability Scanner (SQLi, XSS, Headers, Cookies, TLS)
             ├── Findings & Evidence Engine
             ├── Risk Engine (CVSS v4.0 concepts)
             ├── OWASP Top 10 Analyzer
             ├── AI Security Analyst (OpenAI / Fallback)
             └── Report Generator (ReportLab PDF)
                      │
                      ▼
               DATABASE (MySQL / SQLite ORM Models)
```

---

## 3. Technology Stack

- **Backend Runtime**: Python 3.11+
- **Web Framework**: Flask 3.0+, Flask-SQLAlchemy, Flask-Login, Flask-WTF
- **Database**: MySQL 8.0+ / SQLite, SQLAlchemy 2.0 ORM, PyMySQL
- **Security & Inspection**: Cryptography, Requests, BeautifulSoup4
- **Reporting**: ReportLab
- **AI Integration**: OpenAI API (optional, with deterministic offline fallback)
- **Testing**: Pytest, Pytest-Flask

---

## 4. Project Folder Structure

```
AppSentinel/
├── app.py                     # Application entry point
├── config.py                  # Environment-driven configuration profiles
├── requirements.txt           # Python dependency specifications
├── pytest.ini                 # Pytest test discovery configuration
├── .env.example               # Environment variable template
├── .env                       # Local environment configuration
├── .gitignore                 # Version control exclusion rules
├── README.md                  # Comprehensive documentation
│
├── docs/                      # Technical documentation
│   ├── OWASP_MAPPING.md       # OWASP Top 10:2021 mapping methodology & CWE taxonomy
│   ├── CVSS_V4_RISK_ENGINE.md # CVSS v4.0 specification, MacroVectors, & scoring bands
│   ├── RISK_PRIORITIZATION.md # Operational priority (P1-P5) decision matrix & SLA guide
│   └── REMEDIATION_GUIDE.md   # Secure code examples & verification procedures
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
│   │   ├── __init__.py        # Blueprint exports
│   │   ├── health.py          # / and /api/health monitoring endpoints
│   │   ├── auth.py            # Authentication routes (V2)
│   │   ├── dashboard.py       # Security dashboard routes (V3)
│   │   ├── targets.py         # Target management routes (V4)
│   │   ├── scanner.py         # Scanner engine routes (V5-V6)
│   │   ├── owasp.py           # OWASP Top 10 assessment routes (V7)
│   │   ├── risk.py            # CVSS v4.0 and Risk Engine routes (V7)
│   │   └── reports.py         # Report generation routes (V9)
│   ├── scanner/               # Security scanner engines (V5-V6)
│   ├── security/              # SSRF guard, OWASP mapper, CVSS v4 engine, correlator (V7)
│   ├── ai/                    # AI analysis & deterministic remediation (V8)
│   ├── services/              # Scan orchestration, OWASP services & reporting (V7-V9)
│   ├── templates/             # Jinja2 HTML templates
│   │   ├── owasp/             # OWASP assessment dashboards (V7)
│   │   └── risk/              # Risk assessment & finding risk detail pages (V7)
│   └── static/                # CSS, JavaScript, and static assets
│
├── instance/                  # Local instance files and SQLite storage
├── reports/                   # Generated audit PDF reports
└── tests/                     # Automated test suite (136 test cases)
    ├── conftest.py            # Pytest fixtures and app factory harness
    ├── test_foundation.py     # Base app, security headers, CLI tests
    ├── test_health.py         # Health-check endpoint tests
    ├── test_models.py         # Database model relationships and validations
    ├── test_owasp_2025_mapper.py # OWASP Top 10:2025 mapping tests (V7.1)
    ├── test_owasp_mapper.py   # OWASP Top 10:2021 backward-compatibility tests (V7)
    ├── test_cvss_v4_reference_vectors.py # Official FIRST CVSS v4.0 reference tests (V7.1)
    ├── test_historical_owasp_migrations.py # Multi-version assessment migration tests (V7.1)
    ├── test_risk_engine.py    # CVSS v4.0 scoring & vector validation tests (V7)
    ├── test_finding_correlator.py # Finding correlation & compound threat tests (V7)
    ├── test_remediation_engine.py # Defensive remediation guidance tests (V7)
    └── test_owasp_routes.py   # OWASP & Risk Engine RBAC and route tests (V7)
```

---

## 5. Installation & Setup

### Prerequisites
- Python 3.11 or higher
- MySQL Server 8.0+ (or use default local SQLite)
- Git

### 1. Clone or Open Workspace
```bash
cd "C:\Users\vinnu\OneDrive\Desktop\Application Security project"
```

### 2. Create and Activate Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\activate
```

### 3. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 4. Configure Environment
Copy `.env.example` to `.env`:
```powershell
Copy-Item .env.example .env
```
Adjust database parameters if connecting to MySQL:
```env
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=appsentinel_db
```

### 5. Initialize Database Schema
```powershell
flask init-db
```

---

## 6. Running the Application

Start the local development server:
```powershell
python app.py
```
Or via the Flask CLI:
```powershell
flask run --host=127.0.0.1 --port=5000
```
Open your browser to:
- Main Landing: [http://127.0.0.1:5000/](http://127.0.0.1:5000/)
- Health Monitoring: [http://127.0.0.1:5000/api/health](http://127.0.0.1:5000/api/health)

---

## 7. Running Automated Tests

Run the full automated test suite with verbose reporting:
```powershell
pytest -v
```
### Running Specific Test Modules
```powershell
pytest tests/test_cvss_v4_compliance.py
pytest tests/test_cvss_v4_reference_vectors.py
pytest tests/test_owasp_2025_mapper.py
pytest tests/test_historical_owasp_migrations.py
pytest tests/test_owasp_mapper.py
pytest tests/test_risk_engine.py
pytest tests/test_finding_correlator.py
pytest tests/test_remediation_engine.py
pytest tests/test_owasp_routes.py
pytest tests/test_vulnerability_scanner.py
pytest tests/test_recon.py
pytest tests/test_targets.py
pytest tests/test_auth.py
pytest tests/test_rbac.py
```

---

## 8. Security & Ethical Boundaries

AppSentinel strictly enforces safe, evidence-based defensive auditing principles:
- **SSRF Prevention**: Loopback (`127.0.0.1`, `::1`), private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local metadata addresses (`169.254.169.254`), and post-resolution DNS rebinding are blocked.
- **Strict Authorization**: Scans require verified target ownership (via DNS TXT or HTTP well-known token verification) before reconnaissance or vulnerability assessment.
- **Non-Destructive Testing**: Test payloads are designed strictly for detection (e.g., syntax probes and harmless markers), never for data extraction, credential harvesting, persistent alteration, or denial-of-service.
- **Privacy by Design**: Sensitive session cookies are audited without storing raw values. Discovered API keys and credentials are automatically and immediately redacted.

---

## 9. Development Roadmap

- [x] **V1: Project Foundation** (Core architecture, 10 models, configuration, health API, test suite)
- [x] **V2: Authentication & RBAC** (User registration, login, session security, password hashing, role enforcement)
- [x] **V3: Professional Dark Cyber Dashboard** (Dark SOC UI, metrics cards, Chart.js, statistics)
- [x] **V4: Target Management & Verification** (SSRF validator, DNS TXT & HTTP well-known verification tokens, audit logs)
- [x] **V5: Reconnaissance Engine** (Availability checker, passive tech detector, HTTP auditor, security headers, in-scope crawler, DNS analyzer, metadata parser)
- [x] **V6: Advanced Vulnerability Scanner** (SQLi scanner, XSS scanner, Insecure cookies, Security misconfigurations, Information disclosure, Directory listing, Sensitive data exposure with redaction, Vulnerability Manager, local test lab)
- [x] **V7: OWASP Analyzer & Risk Engine** (OWASP Top 10:2021 mapping, FIRST CVSS v4.0 scoring engine, operational priority P1-P5, finding correlation & compound threats, deterministic remediation advisories, SOC risk dashboards, 112 passing tests)
- [x] **V7.1: OWASP 2025 Upgrade & CVSS v4.0 Validation** (Dual OWASP 2025/2021 support, full FIRST CVSS v4.0 specification audit with EQ1–EQ6 & Threat/Environmental metrics, 14 official reference vectors, historical assessment preservation, 136 passing tests)
- [x] **V7.2: CVSS v4.0 Compliance Audit** (Strict Base SI/SA metric audit rejecting 'S', MSI/MSA safety support triggering EQ4 Level 0, Supplemental Safety S:P/S:N separation, complete Supplemental metrics AU/R/V/RE/U, 'Not Defined' X preservation and scoring equivalence, duplicate metric rejection, CVSS-B/BT/BE/BTE score nomenclature, canonical vector ordering, 161 passing tests)
- [x] **V7.2.1: Final CVSS Validation** (Strict case-sensitive Provider Urgency validation rejecting uppercase/lowercase/invalid strings, test count reconciliation across all 19 test suites, official reference vector coverage distinction, 162 passing tests)
- [ ] **V8: AI Security Analyst**
- [ ] **V9: Professional PDF Report Generator**
- [ ] **V10: Final Integration & Docker Deployment**
