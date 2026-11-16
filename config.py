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


class ProductionConfig(Config):
    """Production configuration with hardened security settings."""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
