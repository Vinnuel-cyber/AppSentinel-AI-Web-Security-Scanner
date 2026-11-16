from .health import health_bp
from .auth import auth_bp
from .dashboard import dashboard_bp
from .targets import targets_bp
from .scanner import scanner_bp
from .reports import reports_bp

__all__ = [
    "health_bp",
    "auth_bp",
    "dashboard_bp",
    "targets_bp",
    "scanner_bp",
    "reports_bp",
]
