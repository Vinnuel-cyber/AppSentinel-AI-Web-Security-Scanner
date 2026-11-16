"""AppSentinel AI Configuration Tests (V8)."""

import os
from unittest.mock import patch
from app.ai.ai_config import AIConfig


def test_ai_config_defaults(app):
    """Test AIConfig default fallbacks when environment variables are unset."""
    with app.app_context():
        # Testing config has AI_ENABLED=False by default
        assert AIConfig.get_provider() == "openai"
        assert AIConfig.get_timeout() == 30
        assert AIConfig.get_max_output_tokens() == 2000
        assert AIConfig.get_daily_limit() == 50


def test_ai_config_env_overrides(monkeypatch):
    """Test AIConfig respects custom environment overrides."""
    monkeypatch.setenv("AI_ENABLED", "true")
    monkeypatch.setenv("AI_PROVIDER", "custom-openai")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-4o")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-override-key")
    monkeypatch.setenv("AI_REQUEST_TIMEOUT", "45")
    monkeypatch.setenv("AI_MAX_OUTPUT_TOKENS", "3500")
    monkeypatch.setenv("AI_DAILY_LIMIT_PER_USER", "100")

    assert AIConfig.is_enabled() is True
    assert AIConfig.get_provider() == "custom-openai"
    assert AIConfig.get_model() == "gpt-4o"
    assert AIConfig.get_api_key() == "sk-test-override-key"
    assert AIConfig.get_timeout() == 45
    assert AIConfig.get_max_output_tokens() == 3500
    assert AIConfig.get_daily_limit() == 100


def test_ai_config_disabled_boolean(monkeypatch):
    """Verify various string formats for disabling AI."""
    for val in ["false", "0", "no", "FALSE"]:
        monkeypatch.setenv("AI_ENABLED", val)
        assert AIConfig.is_enabled() is False

    for val in ["true", "1", "yes", "TRUE"]:
        monkeypatch.setenv("AI_ENABLED", val)
        assert AIConfig.is_enabled() is True
