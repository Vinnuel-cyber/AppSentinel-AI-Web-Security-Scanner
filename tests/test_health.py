def test_health_check_endpoint(client):
    """Verify /api/health returns 200 with operational database status."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "healthy"
    assert data["application"] == "AppSentinel"
    assert "timestamp" in data
    assert "database" in data
    assert data["database"]["status"] == "connected"
    assert data["database"]["engine"] in ("sqlite", "mysql")
    assert data["database"]["latency_ms"] >= 0
