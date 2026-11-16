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
├── app/
│   ├── __init__.py            # Application factory (create_app)
│   ├── models/                # SQLAlchemy ORM database models
│   │   ├── __init__.py        # Model registry and db instance
│   │   ├── user.py            # User, roles, password hashing (scrypt)
│   │   ├── target.py          # Targets, domain parsing, verification tokens
│   │   ├── scan.py            # Scans, ScanURL, ScanLog, ScanSetting
│   │   └── vulnerability.py   # Vulnerability, Evidence, AIAnalysis, Report
│   ├── routes/                # Modular Flask route blueprints
│   │   ├── __init__.py        # Blueprint exports
│   │   ├── health.py          # / and /api/health monitoring endpoints
│   │   ├── auth.py            # Authentication routes (V2)
│   │   ├── dashboard.py       # Security dashboard routes (V3)
│   │   ├── targets.py         # Target management routes (V4)
│   │   ├── scanner.py         # Scanner engine routes (V5-V6)
│   │   └── reports.py         # Report generation routes (V9)
│   ├── scanner/               # Security scanner engines (V5-V6)
│   ├── security/              # SSRF guard, risk scoring, evidence (V7)
│   ├── ai/                    # AI analysis & deterministic remediation (V8)
│   ├── services/              # Scan orchestration & PDF reporting (V9)
│   ├── templates/             # Jinja2 HTML templates
│   └── static/                # CSS, JavaScript, and static assets
│
├── instance/                  # Local instance files and SQLite storage
├── reports/                   # Generated audit PDF reports
└── tests/                     # Automated test suite
    ├── conftest.py            # Pytest fixtures and app factory harness
    ├── test_foundation.py     # Base app, security headers, CLI tests
    ├── test_health.py         # Health-check endpoint tests
    └── test_models.py         # Database model relationships and validations
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
pytest
```
To run specific test categories:
```powershell
pytest tests/test_foundation.py
pytest tests/test_health.py
pytest tests/test_models.py
```

---

## 8. Security & Ethical Boundaries

AppSentinel strictly enforces safe scanning principles:
- **SSRF Prevention**: Loopback (`127.0.0.1`, `::1`), private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and link-local addresses are rejected by default.
- **Authorization**: Scans require registered targets with verified ownership tokens before active assessment.
- **Non-Destructive Testing**: Test payloads are designed strictly for detection, never for data extraction or denial-of-service.

---

## 9. Development Roadmap

- [x] **V1: Project Foundation** (Core architecture, 10 models, configuration, health API, test suite)
- [ ] **V2: Authentication & RBAC**
- [ ] **V3: Professional Dark Cyber Dashboard**
- [ ] **V4: Target Management & Verification**
- [ ] **V5: Reconnaissance Engine**
- [ ] **V6: Active & Passive Vulnerability Scanners**
- [ ] **V7: OWASP Analyzer & Risk Engine**
- [ ] **V8: AI Security Analyst**
- [ ] **V9: Professional PDF Report Generator**
- [ ] **V10: Final Integration & Docker Deployment**
