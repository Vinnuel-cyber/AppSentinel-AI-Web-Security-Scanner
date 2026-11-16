import pytest
import socket
from app.security.target_validator import TargetValidator, TargetValidationError


def test_valid_http_and_https_urls():
    """Verify standard public HTTP and HTTPS URLs pass validation."""
    norm_url, domain, ips = TargetValidator.validate_target_url("https://example.com/login?ref=1")
    assert norm_url.startswith("https://example.com/login")
    assert domain == "example.com"
    assert len(ips) > 0

    norm_http, domain_http, ips_http = TargetValidator.validate_target_url("http://example.org:8080/app")
    assert norm_http == "http://example.org:8080/app"
    assert domain_http == "example.org"


def test_reject_unsupported_schemes():
    """Verify schemes other than http and https are rejected."""
    for scheme in ("ftp://example.com", "file:///etc/passwd", "gopher://example.com", "ssh://example.com"):
        with pytest.raises(TargetValidationError, match="Unsupported scheme"):
            TargetValidator.validate_target_url(scheme)


def test_reject_embedded_credentials():
    """Verify URLs with embedded credentials are strictly blocked."""
    with pytest.raises(TargetValidationError, match="embedded credentials"):
        TargetValidator.validate_target_url("https://admin:secret@example.com/dashboard")


def test_ssrf_blocking_localhost_literals():
    """Verify localhost strings and loopback IPs are blocked."""
    for bad_target in (
        "http://localhost",
        "http://localhost:8080",
        "http://127.0.0.1",
        "http://127.0.0.2:5000",
        "http://[::1]/admin",
    ):
        with pytest.raises(TargetValidationError, match="blocked|prohibited|restricted"):
            TargetValidator.validate_target_url(bad_target)


def test_ssrf_blocking_private_ipv4_ranges():
    """Verify RFC 1918 private IPv4 addresses are blocked."""
    for private_ip in (
        "http://10.0.0.1",
        "http://10.254.254.254/api",
        "http://172.16.0.1",
        "http://172.31.255.255",
        "http://192.168.0.1",
        "http://192.168.1.254",
    ):
        with pytest.raises(TargetValidationError, match="blocked|Private address"):
            TargetValidator.validate_target_url(private_ip)


def test_ssrf_blocking_link_local_and_cloud_metadata():
    """Verify link-local (169.254.x.x) AWS/GCP/Azure metadata address is blocked."""
    with pytest.raises(TargetValidationError, match="Link-local|blocked"):
        TargetValidator.validate_target_url("http://169.254.169.254/latest/meta-data/")


def test_ssrf_dns_resolving_to_private_ip(monkeypatch):
    """Verify domain resolving to private IP space is blocked via DNS resolution check."""
    def fake_getaddrinfo(host, port, proto=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.100", 80))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises(TargetValidationError, match="restricted|Private address"):
        TargetValidator.validate_target_url("http://spoofed-internal.example.com")


def test_dns_rebinding_defense_during_http_verification(monkeypatch):
    """Verify HTTP verification re-resolves and blocks if DNS rebinds to loopback."""
    def fake_getaddrinfo(host, port, proto=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises(TargetValidationError, match="restricted|Loopback"):
        TargetValidator.verify_ownership_via_http("rebound.example.com", "any-token")
