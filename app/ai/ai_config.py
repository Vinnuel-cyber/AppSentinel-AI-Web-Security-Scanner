"""AppSentinel AI Configuration Management (V8).

Manages configuration for the AI Security Analyst module:
- Provider abstraction settings (OpenAI default, extensible).
- API credentials & endpoints (read strictly from environment / app config).
- Timeouts, token caps, rate limits, and fallback toggles.
"""

import os
from flask import current_app


class AIConfig:
    """Encapsulates runtime AI configuration and safety thresholds."""

    DEFAULT_PROVIDER = "openai"
    DEFAULT_MODEL = "gpt-4o-mini"
    DEFAULT_TIMEOUT = 30
    DEFAULT_MAX_OUTPUT_TOKENS = 2000
    DEFAULT_DAILY_LIMIT = 50

    @classmethod
    def is_enabled(cls) -> bool:
        """Check whether cloud AI analysis is enabled."""
        if "AI_ENABLED" in os.environ:
            return os.getenv("AI_ENABLED", "false").lower() in ("true", "1", "yes")
        if current_app:
            return bool(current_app.config.get("AI_ENABLED", False))
        return False

    @classmethod
    def get_provider(cls) -> str:
        """Get the configured AI provider name."""
        if "AI_PROVIDER" in os.environ:
            return os.environ["AI_PROVIDER"].lower()
        if current_app and "AI_PROVIDER" in current_app.config:
            return str(current_app.config["AI_PROVIDER"]).lower()
        return cls.DEFAULT_PROVIDER

    @classmethod
    def get_api_key(cls) -> str:
        """Get the OpenAI API key from secure backend configuration."""
        if "OPENAI_API_KEY" in os.environ:
            return os.environ["OPENAI_API_KEY"]
        if current_app and "OPENAI_API_KEY" in current_app.config:
            return current_app.config.get("OPENAI_API_KEY", "") or ""
        return ""

    @classmethod
    def get_model(cls) -> str:
        """Get the configured model identifier."""
        if "OPENAI_MODEL" in os.environ:
            return os.environ["OPENAI_MODEL"]
        if current_app and "OPENAI_MODEL" in current_app.config:
            return current_app.config.get("OPENAI_MODEL", cls.DEFAULT_MODEL) or cls.DEFAULT_MODEL
        return cls.DEFAULT_MODEL

    @classmethod
    def get_timeout(cls) -> int:
        """Get the request timeout in seconds."""
        if "AI_REQUEST_TIMEOUT" in os.environ:
            return int(os.environ["AI_REQUEST_TIMEOUT"])
        if current_app and "AI_REQUEST_TIMEOUT" in current_app.config:
            return int(current_app.config["AI_REQUEST_TIMEOUT"])
        return cls.DEFAULT_TIMEOUT

    @classmethod
    def get_max_output_tokens(cls) -> int:
        """Get the maximum output tokens permitted per analysis."""
        if "AI_MAX_OUTPUT_TOKENS" in os.environ:
            return int(os.environ["AI_MAX_OUTPUT_TOKENS"])
        if current_app and "AI_MAX_OUTPUT_TOKENS" in current_app.config:
            return int(current_app.config["AI_MAX_OUTPUT_TOKENS"])
        return cls.DEFAULT_MAX_OUTPUT_TOKENS

    @classmethod
    def get_daily_limit(cls) -> int:
        """Get the per-user daily AI request limit."""
        if "AI_DAILY_LIMIT_PER_USER" in os.environ:
            return int(os.environ["AI_DAILY_LIMIT_PER_USER"])
        if current_app and "AI_DAILY_LIMIT_PER_USER" in current_app.config:
            return int(current_app.config["AI_DAILY_LIMIT_PER_USER"])
        return cls.DEFAULT_DAILY_LIMIT

    @classmethod
    def is_provider_configured(cls) -> bool:
        """Check whether cloud provider credentials are present and validly formatted."""
        key = cls.get_api_key()
        return bool(key and len(key.strip()) > 5)

    @classmethod
    def get_status(cls) -> dict:
        """Return operational status summary for UI and health diagnostics."""
        enabled = cls.is_enabled()
        configured = cls.is_provider_configured()
        provider = cls.get_provider()
        model = cls.get_model()

        if not enabled:
            mode = "DISABLED"
            detail = "Cloud AI is disabled. Deterministic fallback engine is active."
        elif not configured:
            mode = "UNCONFIGURED"
            detail = "Cloud AI is enabled, but OPENAI_API_KEY is not set. Operating in deterministic fallback mode."
        else:
            mode = "ACTIVE"
            detail = f"AI Analyst connected via {provider} ({model})."

        return {
            "ai_enabled": enabled,
            "provider_configured": configured,
            "provider": provider,
            "model": model,
            "operational_mode": mode,
            "status_message": detail,
            "timeout_seconds": cls.get_timeout(),
            "max_tokens": cls.get_max_output_tokens(),
            "daily_limit": cls.get_daily_limit(),
        }
