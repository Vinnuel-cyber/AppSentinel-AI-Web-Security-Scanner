from datetime import datetime, timezone
from . import db


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    scan_type = db.Column(db.String(32), default="passive", nullable=False)  # passive, active, full
    status = db.Column(db.String(32), default="pending", nullable=False, index=True)  # pending, running, completed, failed, cancelled
    
    risk_score = db.Column(db.Float, default=0.0, nullable=False)  # 0.0 to 100.0 or 0.0 to 10.0
    overall_risk = db.Column(db.String(20), default="Informational", nullable=False)  # Critical, High, Medium, Low, Informational
    
    total_vulnerabilities = db.Column(db.Integer, default=0, nullable=False)
    critical_count = db.Column(db.Integer, default=0, nullable=False)
    high_count = db.Column(db.Integer, default=0, nullable=False)
    medium_count = db.Column(db.Integer, default=0, nullable=False)
    low_count = db.Column(db.Integer, default=0, nullable=False)
    info_count = db.Column(db.Integer, default=0, nullable=False)
    
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    duration_seconds = db.Column(db.Integer, default=0, nullable=False)
    error_message = db.Column(db.Text, nullable=True)
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    urls = db.relationship("ScanURL", backref="scan", lazy="dynamic", cascade="all, delete-orphan")
    vulnerabilities = db.relationship("Vulnerability", backref="scan", lazy="dynamic", cascade="all, delete-orphan")
    logs = db.relationship("ScanLog", backref="scan", lazy="dynamic", cascade="all, delete-orphan")
    reports = db.relationship("Report", backref="scan", lazy="dynamic", cascade="all, delete-orphan")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "target_id": self.target_id,
            "user_id": self.user_id,
            "scan_type": self.scan_type,
            "status": self.status,
            "risk_score": self.risk_score,
            "overall_risk": self.overall_risk,
            "total_vulnerabilities": self.total_vulnerabilities,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<Scan id={self.id} target_id={self.target_id} status='{self.status}'>"


class ScanURL(db.Model):
    __tablename__ = "scan_urls"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    url = db.Column(db.String(1024), nullable=False)
    method = db.Column(db.String(10), default="GET", nullable=False)
    status_code = db.Column(db.Integer, nullable=True)
    response_time_ms = db.Column(db.Integer, default=0, nullable=False)
    content_type = db.Column(db.String(100), nullable=True)
    discovered_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "url": self.url,
            "method": self.method,
            "status_code": self.status_code,
            "response_time_ms": self.response_time_ms,
            "content_type": self.content_type,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
        }


class ScanLog(db.Model):
    __tablename__ = "scan_logs"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    level = db.Column(db.String(10), default="INFO", nullable=False)  # DEBUG, INFO, WARN, ERROR
    module = db.Column(db.String(50), default="engine", nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "level": self.level,
            "module": self.module,
            "message": self.message,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


class ScanSetting(db.Model):
    __tablename__ = "scan_settings"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    name = db.Column(db.String(100), default="Default Profile", nullable=False)
    max_depth = db.Column(db.Integer, default=3, nullable=False)
    max_urls = db.Column(db.Integer, default=50, nullable=False)
    timeout_seconds = db.Column(db.Integer, default=10, nullable=False)
    
    # Active scanner toggle flags
    enable_sqli = db.Column(db.Boolean, default=True, nullable=False)
    enable_xss = db.Column(db.Boolean, default=True, nullable=False)
    enable_headers = db.Column(db.Boolean, default=True, nullable=False)
    enable_cookies = db.Column(db.Boolean, default=True, nullable=False)
    enable_tls = db.Column(db.Boolean, default=True, nullable=False)
    enable_info_disc = db.Column(db.Boolean, default=True, nullable=False)
    
    user_agent = db.Column(db.String(255), default="AppSentinel-Security-Scanner/1.0", nullable=False)
    custom_headers = db.Column(db.Text, nullable=True)  # JSON formatted custom headers
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "max_depth": self.max_depth,
            "max_urls": self.max_urls,
            "timeout_seconds": self.timeout_seconds,
            "enable_sqli": self.enable_sqli,
            "enable_xss": self.enable_xss,
            "enable_headers": self.enable_headers,
            "enable_cookies": self.enable_cookies,
            "enable_tls": self.enable_tls,
            "enable_info_disc": self.enable_info_disc,
            "user_agent": self.user_agent,
        }
