def test_app_creation(app):
    """Verify Flask application initializes with testing configuration."""
    assert app is not None
    assert app.config["TESTING"] is True
    assert app.config["WTF_CSRF_ENABLED"] is False


def test_index_endpoint(client):
    """Verify root index endpoint returns application identity metadata."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.get_json()
    assert data["app"] == "AppSentinel"
    assert "version" in data
    assert data["status"] == "operational"


def test_security_headers_present(client):
    """Verify all critical security headers are attached to HTTP responses."""
    response = client.get("/")
    headers = response.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-XSS-Protection") == "1; mode=block"
    assert "strict-origin" in headers.get("Referrer-Policy", "")
    assert "Content-Security-Policy" in headers


def test_404_error_handler(client):
    """Verify missing endpoints return structured JSON 404 response."""
    response = client.get("/nonexistent-endpoint-xyz")
    assert response.status_code == 404
    data = response.get_json()
    assert data["error"] == "Not Found"


def test_init_db_cli_command(runner):
    """Verify flask init-db CLI command creates database tables successfully."""
    result = runner.invoke(args=["init-db"])
    assert result.exit_code == 0
    assert "created successfully" in result.output
