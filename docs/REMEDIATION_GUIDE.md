# Web Application Security Remediation Guide

This guide provides concrete, framework-specific remediation recommendations, secure coding patterns, and verification procedures for vulnerabilities identified by AppSentinel's scanning and risk engines.

---

## 1. SQL Injection (`A03:2021 - Injection`, `CWE-89`)

### 1.1 Remediation Philosophy
Never construct dynamic SQL statements using string concatenation, string formatting (f-strings), or string replacement with user-supplied data. Always use parameterized queries, prepared statements, or an Object-Relational Mapper (ORM) with bound parameters.

### 1.2 Secure Code Implementations

#### Python / SQLAlchemy ORM
```python
# VULNERABLE: Direct string interpolation into raw SQL
# cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")

# SECURE: Using SQLAlchemy bound parameters
from sqlalchemy import text

stmt = text("SELECT id, username, email FROM users WHERE username = :uname")
result = db.session.execute(stmt, {"uname": username}).fetchone()

# OR SECURE: Using ORM Query API
user = db.session.query(User).filter(User.username == username).first()
```

#### Node.js / PostgreSQL (`pg`)
```javascript
// SECURE: Parameterized query with $1 placeholders
const query = 'SELECT id, username, email FROM users WHERE username = $1';
const values = [req.body.username];
const result = await pool.query(query, values);
```

### 1.3 Verification Procedure
1. Send syntax probe payloads containing single quotes (`'`), double quotes (`"`), and boolean conditions (`' OR '1'='1`).
2. Verify the application treats the input strictly as literal data without throwing database syntax exceptions or altering query logic.
3. Confirm automated tests pass: `pytest tests/test_vulnerability_scanner.py -k sqli`.

---

## 2. Reflected Cross-Site Scripting (`A03:2021 - Injection`, `CWE-79`)

### 2.1 Remediation Philosophy
Apply context-aware output encoding before rendering user input into HTML, HTML attributes, JavaScript contexts, or URLs. Enforce a defense-in-depth Content Security Policy (CSP) to restrict script execution.

### 2.2 Secure Code Implementations

#### Python / Flask (Jinja2)
```html
<!-- SECURE: Jinja2 automatically escapes HTML by default -->
<p>Welcome, {{ username }}</p>

<!-- DANGEROUS: Never use |safe on untrusted input -->
<!-- <p>Welcome, {{ username | safe }}</p> -->
```

#### Client-Side JavaScript
```javascript
// SECURE: Use textContent instead of innerHTML
const userGreeting = document.getElementById('greeting');
userGreeting.textContent = untrustedInput;

// SECURE: If HTML is required, sanitize using DOMPurify
import DOMPurify from 'dompurify';
userGreeting.innerHTML = DOMPurify.sanitize(untrustedInput);
```

### 2.3 Verification Procedure
1. Submit benign probe payload: `<script>/*probe*/</script>` or `<img src=x onerror=alert(1)>`.
2. Inspect the raw HTTP response body to confirm all HTML entities are safely encoded (`&lt;script&gt;` instead of `<script>`).
3. Confirm the browser renders the string as plain text without script execution.

---

## 3. Insecure Session Cookie Attributes (`A05:2021`, `CWE-614`, `CWE-1004`)

### 3.1 Remediation Philosophy
All session identifiers and authentication tokens must be protected with the following attributes:
- `HttpOnly`: Blocks client-side JavaScript access via `document.cookie` (mitigates session hijacking via XSS).
- `Secure`: Ensures the cookie is transmitted only over encrypted TLS/HTTPS connections.
- `SameSite=Lax` or `SameSite=Strict`: Restricts cookie inclusion in cross-site requests (mitigates CSRF).

### 3.2 Secure Configuration

#### Flask Application (`config.py`)
```python
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = 'Lax'
PERMANENT_SESSION_LIFETIME = timedelta(minutes=60)
```

#### Express.js (`express-session`)
```javascript
app.use(session({
    secret: process.env.SESSION_SECRET,
    cookie: {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        maxAge: 3600000
    }
}));
```

---

## 4. Missing HTTP Security Headers (`A05:2021`, `CWE-1021`, `CWE-693`)

### 4.1 Recommended Header Baseline

```http
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none';
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), camera=(), microphone=()
```

### 4.2 Web Server Implementations

#### Nginx (`nginx.conf`)
```nginx
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'; object-src 'none';" always;
```

#### Flask (`app/__init__.py`)
```python
@app.after_request
def apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
```

---

## 5. Information Disclosure & Open Directory Listing (`A01:2021`, `A05:2021`)

### 5.1 Disable Directory Listing
- **Nginx**: Ensure `autoindex off;` is configured within all `location` blocks.
- **Apache**: Include `Options -Indexes` in `httpd.conf` or `.htaccess`.

### 5.2 Suppress Server Banners & Diagnostic Stack Traces
- **Nginx**: Set `server_tokens off;`.
- **Apache**: Set `ServerTokens Prod` and `ServerSignature Off`.
- **Flask**: Ensure `DEBUG = False` in production environments and register a custom 500 error handler that returns a generic error message without stack traces.

---

## 6. Official References & Standards
- [OWASP Top 10:2021 Standard](https://owasp.org/Top10/)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [FIRST CVSS v4.0 Specification Guide](https://www.first.org/cvss/v4.0/specification-document)
- [RFC 6265bis: Cookies - HTTP State Management Mechanism](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis)
