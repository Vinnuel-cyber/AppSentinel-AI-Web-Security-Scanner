import pytest
from unittest.mock import MagicMock
import requests
from requests.exceptions import Timeout, SSLError, ConnectionError
from app.models import (
    db,
    User,
    Target,
    ReconScan,
    DiscoveredEndpoint,
    TechnologyFingerprint,
    DNSRecord,
    SecurityHeaderFinding,
    WebsiteMetadata,
)
from app.scanner import (
    AvailabilityChecker,
    TechnologyDetector,
    HTTPAnalyzer,
    SecurityHeadersAnalyzer,
    EndpointDiscoveryEngine,
    DNSAnalyzer,
    MetadataAnalyzer,
)
from app.services.recon_manager import ReconManager, ReconAuthorizationError
from app.security.target_validator import TargetValidator


@pytest.fixture
def recon_users(app):
    """Fixture providing standard user, second user, and admin."""
    with app.app_context():
        alice = User(username="alice_recon", email="alice@recon.test", role="USER")
        alice.set_password("AliceSecure123!")
        bob = User(username="bob_recon", email="bob@recon.test", role="USER")
        bob.set_password("BobSecure1234!")
        admin = User(username="admin_recon", email="admin@recon.test", role="ADMIN")
        admin.set_password("AdminSecure123!")
        db.session.add_all([alice, bob, admin])
        db.session.commit()
        return alice.id, bob.id, admin.id


@pytest.fixture
def verified_target(app, recon_users, monkeypatch):
    """Fixture providing a verified target owned by Alice."""
    alice_id, _, _ = recon_users
    with app.app_context():
        target = Target(
            name="Authorized Corp App",
            target_url="https://authorized.example.com",
            domain="authorized.example.com",
            owner_id=alice_id,
            is_verified=True,
            verification_status="VERIFIED",
            verification_method="dns_txt",
            environment="Production",
        )
        db.session.add(target)
        db.session.commit()
        return target.id


# =========================================================================
# 1. Availability Engine Unit Tests
# =========================================================================

def test_availability_online_status(monkeypatch):
    """Test availability engine correctly classifies 200 OK as ONLINE with headers and latency."""
    monkeypatch.setattr(TargetValidator, "validate_target_url", lambda url, allow_private=False: (url, "example.com", ["93.184.216.34"]))

    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.url = "https://example.com/"
    fake_resp.headers = {"Server": "nginx/1.24.0", "Content-Type": "text/html"}
    fake_resp.content = b"<html><body>Welcome</body></html>"
    fake_resp.text = "<html><body>Welcome</body></html>"
    fake_resp.history = []

    monkeypatch.setattr(requests.Session, "get", lambda *args, **kwargs: fake_resp)

    res = AvailabilityChecker.check_availability("https://example.com")
    assert res["status"] == "ONLINE"
    assert res["is_online"] is True
    assert res["http_status"] == 200
    assert res["server_header"] == "nginx/1.24.0"
    assert res["ip_address"] == "93.184.216.34"


def test_availability_offline_status(monkeypatch):
    """Test availability engine classifies ConnectionError as OFFLINE."""
    monkeypatch.setattr(TargetValidator, "validate_target_url", lambda url, allow_private=False: (url, "example.com", ["93.184.216.34"]))
    
    def raise_conn(*args, **kwargs):
        raise ConnectionError("Connection refused by remote host")

    monkeypatch.setattr(requests.Session, "get", raise_conn)

    res = AvailabilityChecker.check_availability("https://example.com")
    assert res["status"] == "OFFLINE"
    assert res["is_online"] is False
    assert "Connection refused" in res["error_message"]


def test_availability_timeout_status(monkeypatch):
    """Test availability engine classifies request Timeout as TIMEOUT."""
    monkeypatch.setattr(TargetValidator, "validate_target_url", lambda url, allow_private=False: (url, "example.com", ["93.184.216.34"]))

    def raise_timeout(*args, **kwargs):
        raise Timeout("Read timed out")

    monkeypatch.setattr(requests.Session, "get", raise_timeout)

    res = AvailabilityChecker.check_availability("https://example.com")
    assert res["status"] == "TIMEOUT"
    assert res["is_online"] is False


def test_availability_ssl_error_status(monkeypatch):
    """Test availability engine classifies SSL handshake error as SSL_ERROR."""
    monkeypatch.setattr(TargetValidator, "validate_target_url", lambda url, allow_private=False: (url, "example.com", ["93.184.216.34"]))

    def raise_ssl(*args, **kwargs):
        raise SSLError("Certificate verify failed: self-signed certificate")

    monkeypatch.setattr(requests.Session, "get", raise_ssl)

    res = AvailabilityChecker.check_availability("https://example.com")
    assert res["status"] == "SSL_ERROR"
    assert res["is_online"] is False


def test_availability_blocked_waf_status(monkeypatch):
    """Test availability engine identifies WAF blocking via 403 + Cloudflare signature."""
    monkeypatch.setattr(TargetValidator, "validate_target_url", lambda url, allow_private=False: (url, "example.com", ["93.184.216.34"]))

    fake_resp = MagicMock()
    fake_resp.status_code = 403
    fake_resp.url = "https://example.com/"
    fake_resp.headers = {"Server": "cloudflare"}
    fake_resp.content = b"<html>Attention Required! | Cloudflare</html>"
    fake_resp.text = "<html>Attention Required! | Cloudflare</html>"
    fake_resp.history = []

    monkeypatch.setattr(requests.Session, "get", lambda *args, **kwargs: fake_resp)

    res = AvailabilityChecker.check_availability("https://example.com")
    assert res["status"] == "BLOCKED"
    assert res["is_online"] is True


# =========================================================================
# 2. Technology Detector Unit Tests
# =========================================================================

def test_technology_detection_signatures():
    """Verify passive detection across headers, cookies, meta tags, and script tags."""
    headers = {
        "Server": "nginx/1.22.1",
        "X-Powered-By": "Express",
        "cf-ray": "848202b29c1e-IAD",
    }
    cookies = {
        "connect.sid": "s%3A12345.xyz",
        "csrftoken": "tok123",
    }
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="generator" content="WordPress 6.4.2">
        <script src="/static/js/react.production.min.js"></script>
        <script src="https://cdn.example.com/jquery-3.6.0.min.js"></script>
    </head>
    <body>
        <div class="content">App Content</div>
    </body>
    </html>
    """

    results = TechnologyDetector.detect(headers, html_content=html, cookies=cookies)
    names = {r["name"] for r in results}

    assert "Nginx" in names
    assert "Express.js" in names
    assert "Cloudflare" in names
    assert "WordPress" in names
    assert "React" in names
    assert "jQuery" in names
    assert "Django" in names

    # Verify version detection
    nginx_det = next(r for r in results if r["name"] == "Nginx")
    assert nginx_det["version"] == "1.22.1"
    assert nginx_det["confidence"] == "HIGH"


# =========================================================================
# 3. Security Headers Analyzer Unit Tests
# =========================================================================

def test_security_headers_evaluation_optimal():
    """Verify all optimal security headers pass without warnings."""
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=()",
    }

    findings = SecurityHeadersAnalyzer.evaluate(headers, is_https=True)
    assert len(findings) == 6
    for f in findings:
        assert f["present"] is True
        assert f["status"] == "OPTIMAL"


def test_security_headers_evaluation_missing_and_suboptimal():
    """Verify missing headers are assigned appropriate risk and remediation."""
    headers = {
        "X-Frame-Options": "ALLOWALL",  # Deprecated/suboptimal
        "Content-Security-Policy": "script-src 'unsafe-inline'",  # Suboptimal
    }

    findings = SecurityHeadersAnalyzer.evaluate(headers, is_https=True)
    status_map = {f["header_name"]: f for f in findings}

    # HSTS missing
    assert status_map["Strict-Transport-Security"]["present"] is False
    assert status_map["Strict-Transport-Security"]["status"] == "MISSING"
    assert status_map["Strict-Transport-Security"]["risk_level"] == "MEDIUM"

    # X-Frame-Options suboptimal
    assert status_map["X-Frame-Options"]["present"] is True
    assert status_map["X-Frame-Options"]["status"] == "SUBOPTIMAL"

    # CSP suboptimal
    assert status_map["Content-Security-Policy"]["present"] is True
    assert status_map["Content-Security-Policy"]["status"] == "SUBOPTIMAL"


# =========================================================================
# 4. Endpoint Discovery Unit Tests
# =========================================================================

def test_endpoint_discovery_scope_and_extraction(monkeypatch):
    """Verify endpoints are extracted safely and external links are excluded."""
    base_url = "https://corp.test"
    auth_domain = "corp.test"

    html = """
    <html>
        <body>
            <a href="/login">Login</a>
            <a href="https://corp.test/dashboard">Dashboard</a>
            <a href="https://evil-external.com/phish">External Link</a>
            <a href="javascript:void(0)">JS Void</a>
            <a href="mailto:admin@corp.test">Email</a>
            <form action="/api/v1/auth" method="POST">
                <input type="text" name="user">
            </form>
            <script src="/static/bundle.js"></script>
        </body>
    </html>
    """

    # Mock robots.txt and sitemap.xml
    monkeypatch.setattr(EndpointDiscoveryEngine, "extract_from_robots", lambda *args, **kwargs: [
        {"url": "https://corp.test/admin", "http_method": "GET", "source": "robots_txt", "status_code": None, "content_type": None}
    ])
    monkeypatch.setattr(EndpointDiscoveryEngine, "extract_from_sitemap", lambda *args, **kwargs: [
        {"url": "https://corp.test/about", "http_method": "GET", "source": "sitemap_xml", "status_code": None, "content_type": None}
    ])

    results = EndpointDiscoveryEngine.discover_all(base_url, auth_domain, html_content=html)
    urls = {r["url"] for r in results}

    assert "https://corp.test/login" in urls
    assert "https://corp.test/dashboard" in urls
    assert "https://corp.test/api/v1/auth" in urls
    assert "https://corp.test/static/bundle.js" in urls
    assert "https://corp.test/admin" in urls
    assert "https://corp.test/about" in urls

    # Assert external and dangerous links are rejected
    assert "https://evil-external.com/phish" not in urls
    assert not any("mailto:" in u for u in urls)
    assert not any("javascript:" in u for u in urls)


# =========================================================================
# 5. Metadata Analyzer Unit Tests
# =========================================================================

def test_metadata_extraction():
    """Verify extraction of title, description, generator, canonical, and OpenGraph."""
    html = """
    <html lang="en">
    <head>
        <title>AppSentinel Portal</title>
        <meta name="description" content="AI-Powered Security Auditing Platform">
        <meta name="generator" content="AppSentinel Core v2">
        <link rel="canonical" href="https://portal.example.com/canonical">
        <meta property="og:title" content="AppSentinel Portal">
        <meta property="og:type" content="website">
    </head>
    <body>Welcome</body>
    </html>
    """

    meta = MetadataAnalyzer.extract_metadata(html)
    assert meta["title"] == "AppSentinel Portal"
    assert meta["description"] == "AI-Powered Security Auditing Platform"
    assert meta["generator"] == "AppSentinel Core v2"
    assert meta["canonical_url"] == "https://portal.example.com/canonical"
    assert meta["language"] == "en"
    assert meta["open_graph"]["title"] == "AppSentinel Portal"
    assert meta["open_graph"]["type"] == "website"


# =========================================================================
# 6. Target Authorization & RBAC Enforcement Tests
# =========================================================================

def test_recon_unverified_target_rejected(client, recon_users):
    """Test unverified targets cannot be scanned."""
    alice_id, _, _ = recon_users
    with client.application.app_context():
        user = db.session.get(User, alice_id)
        unverified = Target(
            name="Unverified Target",
            target_url="https://unverified.test",
            domain="unverified.test",
            owner_id=alice_id,
            is_verified=False,
            verification_status="PENDING_VERIFICATION",
        )
        db.session.add(unverified)
        db.session.commit()

        with pytest.raises(ReconAuthorizationError) as exc_info:
            ReconManager.validate_target_for_recon(unverified, user)
        assert "not verified" in str(exc_info.value)


def test_recon_cross_user_isolation(client, recon_users, verified_target):
    """Test Bob cannot trigger or view Alice's target recon."""
    _, bob_id, _ = recon_users
    with client.application.app_context():
        bob = db.session.get(User, bob_id)
        target = db.session.get(Target, verified_target)

        with pytest.raises(ReconAuthorizationError) as exc_info:
            ReconManager.validate_target_for_recon(target, bob)
        assert "Unauthorized" in str(exc_info.value)


# =========================================================================
# 7. End-to-End Recon Pipeline & REST API Tests
# =========================================================================

def test_full_recon_pipeline_execution(client, recon_users, verified_target, monkeypatch):
    """Execute complete recon pipeline with mocked network responses and verify database records."""
    alice_id, _, _ = recon_users

    # Mock hostname resolution & SSRF validation
    monkeypatch.setattr(TargetValidator, "resolve_and_validate_hostname", lambda host, allow_private=False: ["93.184.216.34"])

    # Mock availability response
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.url = "https://authorized.example.com/"
    fake_resp.headers = {
        "Server": "nginx/1.24.0",
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
    }
    fake_resp.content = b"<html><head><title>Authorized App</title></head><body><a href='/dashboard'>Dash</a></body></html>"
    fake_resp.text = "<html><head><title>Authorized App</title></head><body><a href='/dashboard'>Dash</a></body></html>"
    fake_resp.cookies.get_dict.return_value = {"csrftoken": "tokenabc"}
    fake_resp.history = []

    monkeypatch.setattr(AvailabilityChecker, "check_availability", lambda *args, **kwargs: {
        "target_url": "https://authorized.example.com",
        "status": "ONLINE",
        "is_online": True,
        "http_status": 200,
        "response_time_ms": 120,
        "final_url": "https://authorized.example.com/",
        "redirects": [],
        "server_header": "nginx/1.24.0",
        "ip_address": "93.184.216.34",
        "error_message": None,
        "raw_response": fake_resp,
    })

    # Mock DNS records
    monkeypatch.setattr(DNSAnalyzer, "resolve_records", lambda domain, timeout=2.0: [
        {"record_type": "A", "name": domain, "value": "93.184.216.34", "ttl": 300},
        {"record_type": "TXT", "name": domain, "value": "v=spf1 -all", "ttl": 3600},
    ])

    # Login as Alice
    client.post("/auth/login", json={"login_id": "alice_recon", "password": "AliceSecure123!"})

    # Trigger scan via POST /recon/start/<target_id>
    response = client.post(f"/recon/start/{verified_target}", json={})
    assert response.status_code == 201
    data = response.get_json()
    scan_id = data["scan_id"]
    assert data["status"] == "completed"

    # Verify JSON findings endpoint GET /recon/findings/<scan_id>
    findings_resp = client.get(f"/recon/findings/{scan_id}")
    assert findings_resp.status_code == 200
    f_data = findings_resp.get_json()

    assert f_data["scan"]["availability_status"] == "ONLINE"
    assert f_data["scan"]["ip_address"] == "93.184.216.34"
    assert len(f_data["dns_records"]) == 2
    assert len(f_data["security_headers"]) > 0
    assert len(f_data["technologies"]) > 0
    assert len(f_data["endpoints"]) >= 1
    assert f_data["metadata"]["title"] == "Authorized App"


def test_recon_cancel_flow(client, recon_users, verified_target):
    """Test cancelling an in-flight or pending scan."""
    alice_id, _, _ = recon_users
    client.post("/auth/login", json={"login_id": "alice_recon", "password": "AliceSecure123!"})

    # Create a pending scan manually
    with client.application.app_context():
        scan = ReconScan(target_id=verified_target, user_id=alice_id, status="pending")
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

    cancel_resp = client.post(f"/recon/cancel/{scan_id}", json={})
    assert cancel_resp.status_code == 200
    assert cancel_resp.get_json()["message"] == "Scan cancelled successfully."


def test_http_analyzer_cookie_and_cache_audit():
    """Verify HTTP response analysis handles cookie security flags and cache policies without leaking values."""
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.url = "https://app.securecorp.test/api"
    fake_resp.headers = {
        "Content-Type": "application/json",
        "Server": "Caddy",
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0",
    }
    fake_resp.content = b'{"status": "ok"}'
    fake_resp.history = []

    # Mock cookie attributes
    cookie1 = MagicMock()
    cookie1.name = "session_id"
    cookie1.domain = "app.securecorp.test"
    cookie1.path = "/"
    cookie1.secure = True
    cookie1.has_nonstandard_attr.side_effect = lambda attr: attr.lower() == "httponly"
    cookie1.get_nonstandard_attr.side_effect = lambda attr: "Strict" if attr.lower() == "samesite" else None

    cookie2 = MagicMock()
    cookie2.name = "tracker_id"
    cookie2.domain = "app.securecorp.test"
    cookie2.path = "/"
    cookie2.secure = False
    cookie2.has_nonstandard_attr.side_effect = lambda attr: False
    cookie2.get_nonstandard_attr.side_effect = lambda attr: "None" if attr.lower() == "samesite" else None

    fake_resp.cookies = [cookie1, cookie2]

    audit = HTTPAnalyzer.analyze_response(fake_resp, authorized_domain="app.securecorp.test")
    assert audit["status_code"] == 200
    assert audit["cache_policy"]["is_no_store"] is True
    assert audit["cache_policy"]["is_no_cache"] is True
    assert len(audit["cookies"]) == 2

    # Cookie 1 should be fully secure
    assert audit["cookies"][0]["name"] == "session_id"
    assert audit["cookies"][0]["httponly"] is True
    assert audit["cookies"][0]["secure"] is True
    assert audit["cookies"][0]["is_secure_config"] is True

    # Cookie 2 should flag missing flags
    assert audit["cookies"][1]["name"] == "tracker_id"
    assert audit["cookies"][1]["httponly"] is False
    assert audit["cookies"][1]["is_secure_config"] is False


def test_recon_results_cross_user_isolation_route(client, recon_users, verified_target):
    """Test user cannot access results for a scan belonging to another user."""
    alice_id, bob_id, _ = recon_users

    # Create scan belonging to Alice
    with client.application.app_context():
        scan = ReconScan(target_id=verified_target, user_id=alice_id, status="completed")
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

    # Login as Bob
    client.post("/auth/login", json={"login_id": "bob_recon", "password": "BobSecure1234!"})

    # Bob attempts to view Alice's scan results -> 403 Forbidden
    resp = client.get(f"/recon/results/{scan_id}")
    assert resp.status_code == 403

    findings_resp = client.get(f"/recon/findings/{scan_id}")
    assert findings_resp.status_code == 403


def test_admin_can_view_all_scans(client, recon_users, verified_target):
    """Test Admin can view scan results owned by standard users."""
    alice_id, _, admin_id = recon_users

    with client.application.app_context():
        scan = ReconScan(target_id=verified_target, user_id=alice_id, status="completed")
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

    # Login as Admin
    client.post("/auth/login", json={"login_id": "admin_recon", "password": "AdminSecure123!"})

    resp = client.get(f"/recon/results/{scan_id}")
    assert resp.status_code == 200
    assert b"Reconnaissance Report" in resp.data


def test_ssrf_destination_rejected_in_recon(client, recon_users):
    """Verify that private IP / localhost targets are rejected by ReconManager even if marked verified."""
    alice_id, _, _ = recon_users
    with client.application.app_context():
        user = db.session.get(User, alice_id)
        malicious_target = Target(
            name="Internal Metadata Probe",
            target_url="http://169.254.169.254/latest/meta-data/",
            domain="169.254.169.254",
            owner_id=alice_id,
            is_verified=True,
            verification_status="VERIFIED",
        )
        db.session.add(malicious_target)
        db.session.commit()

        with pytest.raises(ReconAuthorizationError) as exc_info:
            ReconManager.validate_target_for_recon(malicious_target, user, allow_private=False)
        assert "destination security validation" in str(exc_info.value)

