# AppSentinel — User Guide & Operator Manual (v10.0-Final)

Welcome to **AppSentinel**, the AI-powered web application security scanner. This manual walks security analysts, developers, and administrators through each capability in the security operations workflow.

---

## 1. Authentication & Account Management

### 1.1. Registration
1. Navigate to `http://127.0.0.1:5000/auth/register`.
2. Provide your **Full Name**, **Username**, **Email Address**, and a secure **Password**.
   - *Password Complexity Requirements*: Minimum 8 characters, at least 1 uppercase letter, 1 lowercase letter, 1 numeric digit, and 1 special symbol (`!@#$%^&*`).
3. Click **Create Account**.

### 1.2. Secure Login
1. Navigate to `/auth/login`.
2. Enter your username or email address and password.
3. Check **Remember Me** if you want your session persisted.
4. *Brute-Force Protection*: After 5 consecutive failed attempts, your IP/account will be throttled for 300 seconds.

---

## 2. Navigating the SOC Security Dashboard

The SOC Dashboard (`/dashboard`) provides real-time situational awareness over your security perimeter:

- **Metrics Cards**:
  - **Targets**: Total registered targets vs. verified targets.
  - **Scans**: Total scans launched vs. completed scans.
  - **Vulnerabilities**: Total findings count categorized into Critical, High, Medium, Low, and Informational.
  - **Reports**: Total generated security assessment reports.
- **AI Analyst Status Banner**: Displays whether AI is active, the connected engine model, and total automated diagnoses performed.
- **Interactive Visualizations (Chart.js)**:
  - **Severity Breakdown**: Doughnut chart illustrating finding proportions.
  - **OWASP Top 10 Distribution**: Horizontal bar chart showing category prevalence.
- **Activity Stream Tables**:
  - **Recent Targets**: Quick access to verified targets and environments.
  - **Recent Scans**: Status, findings tally, and direct links to results.
  - **Recent Reports**: Generated PDF reports ready for download.

---

## 3. Target Management & Ownership Verification

AppSentinel strictly enforces **verified authorization** before scanning or reconnaissance can occur.

### 3.1. Adding a Target
1. In the top navigation bar, click **Targets** -> **Add Target** (`/targets/add`).
2. Fill out target details:
   - **Target Name**: Human-readable identifier (e.g., `Staging Checkout Service`).
   - **Target URL**: Full HTTP or HTTPS URL (e.g., `https://staging.example.com`).
   - **Environment**: Select `Development`, `Staging`, `Production`, or `Testing`.
   - **Description**: Scope details or system notes.
   - **Authorization Confirmation**: Check the mandatory box affirming you own or have explicit written permission to test this host.
3. Click **Save Target**. The target is created with status `PENDING_VERIFICATION`.

### 3.2. Verifying Ownership
On the Target Details page, choose one of two verification methods:

#### Method A: DNS TXT Record (Recommended for Domains)
1. Copy the unique verification token provided (e.g., `appsentinel-challenge=a1b2c3d4...`).
2. Add a `TXT` record at your domain's DNS provider pointing `@` or `_appsentinel` to that token.
3. Click **Verify via DNS**. AppSentinel queries DNS resolvers to confirm the token.

#### Method B: HTTP Well-Known File (Recommended for Web Servers)
1. Place a plain text file containing your token at:
   `http://<your-domain>/.well-known/appsentinel-verification.txt`
2. Click **Verify via HTTP**. AppSentinel fetches the file, verifies IP safety against SSRF, and validates the token.

Once verified, the target badge updates to `VERIFIED` and unlocks scanning capabilities.

---

## 4. Passive Reconnaissance Engine

1. Navigate to **Reconnaissance** in the navigation bar.
2. Select any verified target and click **Start Reconnaissance**.
3. AppSentinel performs safe, passive discovery:
   - **DNS Analysis**: Resolves A, AAAA, MX, and TXT records.
   - **Web Server Fingerprinting**: Inspects `Server`, `X-Powered-By`, and platform response headers.
   - **Technology Detection**: Detects frontend frameworks, runtime environments, and reverse proxies.
   - **Endpoint Discovery**: Extracts in-scope links, scripts, and endpoints from responses.
4. Review findings in the structured Reconnaissance dashboard.

---

## 5. Evidence-Based Vulnerability Scanning

1. Navigate to **Vulnerability Scanner** (`/scanner`).
2. Choose a verified target and click **Launch Scan**.
3. The multi-module engine systematically tests the target:
   - **SQL Injection**: Checks error signatures and syntax differentials on parameters.
   - **Cross-Site Scripting (XSS)**: Tests benign token reflection with context-aware DOM validation.
   - **Security Headers**: Flags missing defensive headers (`Content-Security-Policy`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`).
   - **Cookie Security**: Audits missing `Secure`, `HttpOnly`, or `SameSite` flags on session cookies.
   - **Information Disclosure**: Analyzes response bodies for stack traces, internal IP disclosures, and file paths.
   - **Sensitive Data Exposure**: Detects API keys or credentials, automatically applying redaction before saving.
4. Access scan results via **Scan Results** or the **Vulnerabilities** hub (`/scanner/vulnerabilities`).
5. Every finding includes title, severity, confidence rating, affected URL, parameter, and raw supporting evidence.

---

## 6. OWASP Analyzer & FIRST CVSS v4.0 Risk Engine

1. Navigate to **OWASP Analyzer** (`/owasp`).
2. Click **Run OWASP Assessment** on your target.
   - Choose between default **OWASP Top 10:2025** or historical **OWASP Top 10:2021**.
3. **OWASP Top 10 Mapping**:
   - Categorizes all findings into the appropriate OWASP standard category with rationale and CWE code.
4. **CVSS v4.0 Risk Scoring**:
   - Calculates the official FIRST CVSS v4.0 canonical vector and base score.
   - Evaluates MacroVectors (EQ1 to EQ6).
5. **Operational Risk Prioritization**:
   - Assigns priority tiers from **P1 (Immediate Critical Remediation)** to **P5 (Informational Hardening)** based on CVSS severity, environment exposure, and finding recurrence.

---

## 7. AI Security Analyst

1. Navigate to **AI Security Analyst** (`/ai/analyst`).
2. **Finding Root-Cause Diagnosis**:
   - Click **AI Diagnosis** on any vulnerability.
   - The analyst details the exact architectural root cause, potential impact, and tailored code fixes.
   - *Note*: If offline or `AI_ENABLED=false`, the deterministic fallback engine provides verified, instant recommendations.
3. **Interactive Security Chat**:
   - Query the analyst about your findings, secure coding practices, or remediation verification procedures.
   - The analyst answers with context grounded exclusively in your target's verified findings.

---

## 8. Professional PDF Report Generator

1. Navigate to **Reports** (`/reports`).
2. Click **Generate Report**.
3. Select the scan and target, then choose one of three formats:
   - **Complete Assessment Report**: Comprehensive report covering methodology, target scope, full findings inventory with evidence, OWASP distribution, and remediation guide.
   - **Vulnerability Detail Report**: In-depth technical breakdown of every finding with full CVSS v4.0 vectors, parameters, and evidence snippets.
   - **Executive Summary**: High-level posture analysis, severity breakdown charts, and executive risk metrics designed for stakeholders.
4. Click **Generate PDF**.
5. Once generated, view the report metadata (type, timestamp, page count, and SHA-256 hash).
6. Click **Download PDF** to securely retrieve the report. The server verifies the file's SHA-256 hash on disk before streaming the file.

---

## 9. Administrative Panel (`/admin/users`)

Users with the `ADMIN` role can access the Admin Panel:
- **User Management**: View all registered users, active roles, and last login timestamps.
- **Role Assignment**: Elevate standard users to `ADMIN` or demote accounts.
- **Account Status**: Activate or deactivate user access.
- **Audit Logs**: Review global target registrations, scan executions, and verification history.
