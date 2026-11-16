"""
test_docker_compose_security.py — Security audit and interpolation tests for Docker Compose configuration.
"""
import re
from pathlib import Path


def test_docker_compose_credentials_removed():
    """Verify docker-compose.yml contains no hardcoded credentials or plaintext passwords."""
    compose_path = Path(__file__).resolve().parent.parent / "docker-compose.yml"
    assert compose_path.exists(), "docker-compose.yml must exist"

    content = compose_path.read_text(encoding="utf-8")

    # Insecure hardcoded strings that were previously present
    forbidden_literals = [
        "AppSentinel_Prod_2026!Secure",
        "Root_MySQL_2026!SecurePassword",
        "appsentinel-docker-production-secret-key-change-me",
    ]
    for literal in forbidden_literals:
        assert literal not in content, f"Hardcoded credential literal '{literal}' found in docker-compose.yml"


def test_docker_compose_required_variable_syntax():
    """Verify required secrets use Compose interpolation syntax ${VAR:?error_message}."""
    compose_path = Path(__file__).resolve().parent.parent / "docker-compose.yml"
    content = compose_path.read_text(encoding="utf-8")

    # Required secrets must use ${VAR:?...} syntax
    required_vars = ["SECRET_KEY", "DB_PASSWORD", "MYSQL_ROOT_PASSWORD"]
    for var in required_vars:
        pattern = rf"\$\{{{var}:\?[^}}]+\}}"
        match = re.search(pattern, content)
        assert match is not None, f"Variable '{var}' in docker-compose.yml must enforce required syntax ${{VAR:?error}}"


def test_docker_compose_localhost_binding():
    """Verify web and db ports default to 127.0.0.1 binding rather than 0.0.0.0."""
    compose_path = Path(__file__).resolve().parent.parent / "docker-compose.yml"
    content = compose_path.read_text(encoding="utf-8")

    # Must specify 127.0.0.1 as default host binding
    assert "127.0.0.1" in content, "docker-compose.yml must specify 127.0.0.1 localhost binding"
    assert '"5000:5000"' not in content, "Wildcard 0.0.0.0:5000:5000 port exposure should not be present"
    assert '"3307:3306"' not in content, "Wildcard 0.0.0.0:3307:3306 port exposure should not be present"


def test_docker_compose_database_healthcheck_safety():
    """Verify database healthcheck does not embed plaintext password in YAML."""
    compose_path = Path(__file__).resolve().parent.parent / "docker-compose.yml"
    content = compose_path.read_text(encoding="utf-8")

    # Must use container environment variable evaluation ($$MYSQL_ROOT_PASSWORD)
    assert "$${MYSQL_ROOT_PASSWORD}" in content, (
        "Database healthcheck must reference $${MYSQL_ROOT_PASSWORD} for safe runtime evaluation"
    )
    assert "-pRoot_MySQL" not in content, "Plaintext root password must not appear in healthcheck command"


def test_docker_compose_credential_consistency():
    """Verify MySQL application password is consistent between web and db services."""
    compose_path = Path(__file__).resolve().parent.parent / "docker-compose.yml"
    content = compose_path.read_text(encoding="utf-8")

    # Both services must reference DB_PASSWORD
    web_db_password = re.search(r"DB_PASSWORD=\$\{DB_PASSWORD:\?[^}]+\}", content)
    db_service_password = re.search(r"MYSQL_PASSWORD:\s*\$\{DB_PASSWORD:\?[^}]+\}", content)

    assert web_db_password is not None, "web service must configure DB_PASSWORD via ${DB_PASSWORD:?...}"
    assert db_service_password is not None, "db service must configure MYSQL_PASSWORD via ${DB_PASSWORD:?...}"


def _interpolate_compose_content(content: str, env: dict) -> str:
    """Simulate Docker Compose v2 environment interpolation rules."""
    # Handle $$ -> temporary placeholder
    escaped = content.replace("$$", "\x00ESCAPED_DOLLAR\x00")

    # Match ${VAR:?error} or ${VAR:-default} or ${VAR}
    pattern = re.compile(r"\$\{([A-Za-z0-9_]+)(?::([\?\-])([^}]+))?\}")

    def replacer(match):
        var_name = match.group(1)
        modifier = match.group(2)
        param = match.group(3)

        val = env.get(var_name)
        if modifier == "?":
            if not val:
                raise ValueError(param or f"Variable {var_name} is required")
            return val
        elif modifier == "-":
            return val if val else param
        else:
            return val if val else ""

    result = pattern.sub(replacer, escaped)
    # Restore escaped dollar sign as single $ (Compose behavior for container shell)
    result = result.replace("\x00ESCAPED_DOLLAR\x00", "$")
    return result


def test_docker_compose_config_interpolation_success_and_failure():
    """Verify Docker Compose configuration resolves successfully with safe test variables, and fails on missing secrets."""
    import pytest
    compose_path = Path(__file__).resolve().parent.parent / "docker-compose.yml"
    content = compose_path.read_text(encoding="utf-8")

    # 1. Missing required variables should raise ValueError matching error message
    with pytest.raises(ValueError, match="SECRET_KEY environment variable is required"):
        _interpolate_compose_content(content, {})

    with pytest.raises(ValueError, match="DB_PASSWORD environment variable is required"):
        _interpolate_compose_content(content, {"SECRET_KEY": "valid_secret_key_for_testing"})

    with pytest.raises(ValueError, match="MYSQL_ROOT_PASSWORD environment variable is required"):
        _interpolate_compose_content(content, {
            "SECRET_KEY": "valid_secret_key_for_testing",
            "DB_PASSWORD": "valid_db_password_for_testing",
        })

    # 2. When all required variables are supplied, interpolation succeeds cleanly
    safe_test_env = {
        "SECRET_KEY": "test_safe_secret_key_32_characters",
        "DB_PASSWORD": "test_safe_db_password_12345",
        "MYSQL_ROOT_PASSWORD": "test_safe_root_password_12345",
    }
    interpolated = _interpolate_compose_content(content, safe_test_env)

    # Verify defaults applied
    assert "127.0.0.1:5000:5000" in interpolated
    assert "127.0.0.1:3307:3306" in interpolated
    assert "FLASK_ENV=production" in interpolated
    assert "DB_USER=appsentinel_user" in interpolated
    assert "DB_NAME=appsentinel_db" in interpolated
    assert "-p${MYSQL_ROOT_PASSWORD}" in interpolated

