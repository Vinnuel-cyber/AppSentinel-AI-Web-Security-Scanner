# AppSentinel — Installation & Deployment Guide (v10.0-Final)

This guide provides end-to-end instructions for deploying AppSentinel in both development and production environments.

---

## 1. System Prerequisites

Before installation, ensure your host environment satisfies the following requirements:

- **Operating System**: Linux (Ubuntu 22.04+ / Debian 12+), macOS (13+), or Windows 10/11
- **Python**: Python 3.11 or higher (Python 3.11.9 recommended)
- **Database**:
  - Development / Testing: SQLite (built-in, zero setup required)
  - Production / College Demo: MySQL 8.0+ or MariaDB 10.6+
- **Git**: Git 2.30+
- **Memory**: 2 GB RAM minimum (4 GB recommended)
- **Disk Space**: 1 GB available disk space

---

## 2. Environment Setup

### Step 2.1: Clone or Navigate to Project Directory

```bash
cd "C:\Users\vinnu\OneDrive\Desktop\Application Security project"
```

### Step 2.2: Create and Activate Python Virtual Environment

**On Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**On Linux / macOS (Bash / Zsh):**
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 2.3: Upgrade Package Installer & Install Dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Verify installed core packages:
```bash
python -c "import flask, sqlalchemy, reportlab, bs4, cryptography; print('Core dependencies installed successfully.')"
```

---

## 3. Database Configuration

### Option A: SQLite (Quick Setup / Testing)
No external database service is required. SQLite is used automatically if `DATABASE_URL` is omitted or configured for SQLite.

```ini
DATABASE_URL=sqlite:///appsentinel.db
```

### Option B: MySQL 8.0+ (Production / Enterprise Demo)

1. Log into your MySQL server:
```bash
mysql -u root -p
```

2. Create the database and dedicated application user:
```sql
CREATE DATABASE appsentinel CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'appsentinel_user'@'localhost' IDENTIFIED BY 'StrongPassword123!';
GRANT ALL PRIVILEGES ON appsentinel.* TO 'appsentinel_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

3. Set connection string in `.env`:
```ini
DATABASE_URL=mysql+pymysql://appsentinel_user:StrongPassword123!@localhost:3306/appsentinel
```

---

## 4. Configuration File (`.env`)

Copy the provided environment template to `.env`:

```bash
cp .env.example .env
```

Edit `.env` with your deployment parameters:

| Variable | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `FLASK_APP` | Yes | `app.py` | Flask application entry point |
| `FLASK_ENV` | Yes | `development` | Environment mode (`development` or `production`) |
| `SECRET_KEY` | Yes | *(Random hex)* | Session signing key (generate via `secrets.token_hex(32)`) |
| `DATABASE_URL` | Yes | *(SQLite/MySQL)* | Database connection URI |
| `REPORT_FOLDER` | Yes | `reports` | Filesystem directory for generated PDF reports |
| `AI_ENABLED` | No | `false` | Enable OpenAI API integration (`true` or `false`) |
| `OPENAI_API_KEY` | No | *(Empty)* | OpenAI API key (leave empty to use deterministic fallback) |
| `OPENAI_MODEL` | No | `gpt-4o-mini` | AI model to query when AI is enabled |
| `AI_DAILY_RATE_LIMIT`| No | `50` | Maximum AI requests per non-admin user per day |

> [!NOTE]
> When `AI_ENABLED=false` or `OPENAI_API_KEY` is not provided, AppSentinel operates **100% offline** with full deterministic security analysis, CVSS v4.0 scoring, and remediation recommendations.

---

## 5. Database Initialization & Admin Provisioning

Run the CLI management commands to initialize tables and provision the initial administrator account:

### Initialize Database Schema
```bash
flask init-db
```
Output:
```
Database tables initialized successfully.
```

### Provision Administrator Account
```bash
flask create-admin --username admin --email admin@appsentinel.local --password "AdminPassword123!"
```
Output:
```
Administrator user 'admin' created successfully.
```

---

## 6. Running the Application

### Development Server
```bash
python app.py
```
Or:
```bash
flask run --host=127.0.0.1 --port=5000
```

Access the application in your browser:
- **Application URL**: `http://127.0.0.1:5000`
- **Initial Login**:
  - Username: `admin`
  - Password: `AdminPassword123!`

---

## 7. Automated Test Suite Execution

Execute the full suite of automated unit, integration, and security regression tests:

```bash
pytest -v
```

Expected result:
```
====================== 238 passed in ~24s ======================
```

Run specific test modules:
```bash
pytest -v tests/test_v10_end_to_end_integration.py  # V10 Integration pipeline
pytest -v tests/test_pdf_reports.py                 # PDF generation & integrity
pytest -v tests/test_cvss_v4_compliance.py          # FIRST CVSS v4.0 verification
pytest -v tests/test_ai_prompt_injection.py         # AI sanitization & redaction
```

---

## 8. Troubleshooting

- **Database Connection Error**: Verify MySQL service is active (`systemctl status mysql` or `Get-Service MySQL`) and user permissions are granted.
- **CSRF Token Missing**: When testing via API clients (Postman/Curl), send `X-CSRFToken` header or test using the provided `pytest` client fixtures.
- **PDF Generation Permission Error**: Ensure the directory designated by `REPORT_FOLDER` is writable by the process user. AppSentinel automatically creates this directory on boot if it does not exist.
