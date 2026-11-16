import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env", override=False)


class Config:
    """Base configuration with security defaults."""
    SECRET_KEY = os.getenv("SECRET_KEY", "appsentinel-dev-secret-key-change-in-production")
    
    # Database Settings
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")
    DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
    DB_PORT = os.getenv("DB_PORT", "3306")
    DB_NAME = os.getenv("DB_NAME", "appsentinel_db")
    
    # Application Folders
    INSTANCE_PATH = BASE_DIR / "instance"
    REPORT_FOLDER = BASE_DIR / "reports"
    
    # Fallback or explicit DATABASE_URL
    _env_db_url = os.getenv("DATABASE_URL")
    if _env_db_url:
        if _env_db_url.startswith("sqlite:///") and not _env_db_url.startswith("sqlite:////"):
            rel_path = _env_db_url.replace("sqlite:///", "")
            abs_db = (BASE_DIR / rel_path).resolve().as_posix()
            SQLALCHEMY_DATABASE_URI = f"sqlite:///{abs_db}"
        else:
            SQLALCHEMY_DATABASE_URI = _env_db_url
    else:
        # Build MySQL connection string
        auth = f"{DB_USER}:{DB_PASSWORD}" if DB_PASSWORD else DB_USER
        SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{auth}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"
        
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
    }
    
    # Security Controls
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False  # Set to True in production with TLS
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max payload
    
    # Scanner Configuration
    SCANNER_MAX_CONCURRENCY = int(os.getenv("SCANNER_MAX_CONCURRENCY", "5"))
    SCANNER_REQUEST_TIMEOUT = int(os.getenv("SCANNER_REQUEST_TIMEOUT", "10"))
    SCANNER_ALLOW_PRIVATE_IPS = os.getenv("SCANNER_ALLOW_PRIVATE_IPS", "False").lower() in ("true", "1", "yes")

    # AI Security Analyst Configuration (V8)
    AI_ENABLED = os.getenv("AI_ENABLED", "false").lower() in ("true", "1", "yes")
    AI_PROVIDER = os.getenv("AI_PROVIDER", "openai").lower()
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    AI_REQUEST_TIMEOUT = int(os.getenv("AI_REQUEST_TIMEOUT", "30"))
    AI_MAX_OUTPUT_TOKENS = int(os.getenv("AI_MAX_OUTPUT_TOKENS", "2000"))
    AI_DAILY_LIMIT_PER_USER = int(os.getenv("AI_DAILY_LIMIT_PER_USER", "50"))


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    TESTING = False


class TestingConfig(Config):
    """Testing configuration with in-memory or isolated database."""
    DEBUG = False
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_ENGINE_OPTIONS = {}


INSECURE_SECRET_KEYS = {
    "",
    "appsentinel-dev-secret-key-change-in-production",
    "change-this-to-a-strong-random-secret-key-in-production",
    "replace_with_a_cryptographically_secure_random_key_min_32_chars",
    "appsentinel-docker-production-secret-key-change-me",
    "secret",
    "secret-key",
    "secret_key",
    "changeme",
    "change-me",
    "change_me",
    "password",
    "123456",
    "your_secure_password",
    "your-secret-key-here",
    "your_secret_key_here",
    "admin",
    "default",
}


class ProductionConfig(Config):
    """Production configuration with hardened security settings."""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True

    # In production, SECRET_KEY must come strictly from the environment
    # and must never fall back to a predictable development default
    SECRET_KEY = os.getenv("SECRET_KEY", "")

    @classmethod
    def validate_production_security(cls):
        """Validate that production environment has safe, unguessable secrets configured."""
        secret = (cls.SECRET_KEY or "").strip()
        if not secret:
            raise ValueError(
                "CRITICAL SECURITY CONFIGURATION ERROR: SECRET_KEY environment variable is required in production."
            )
        if secret.lower() in {k.lower() for k in INSECURE_SECRET_KEYS}:
            raise ValueError(
                "CRITICAL SECURITY CONFIGURATION ERROR: SECRET_KEY is set to a known insecure placeholder. "
                "Generate a cryptographically strong secret key using `secrets.token_hex(32)`."
            )
        if len(secret) < 16:
            raise ValueError(
                "CRITICAL SECURITY CONFIGURATION ERROR: SECRET_KEY must be at least 16 characters long."
            )


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
