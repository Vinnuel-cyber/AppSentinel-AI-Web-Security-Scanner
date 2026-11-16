from datetime import datetime, timezone
import json
from . import db


class ReconScan(db.Model):
    __tablename__ = "recon_scans"

    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    status = db.Column(db.String(32), default="pending", nullable=False, index=True)  # pending, running, completed, failed, cancelled
    availability_status = db.Column(db.String(32), default="UNKNOWN", nullable=False)  # ONLINE, OFFLINE, TIMEOUT, SSL_ERROR, BLOCKED, ERROR
    http_status = db.Column(db.Integer, nullable=True)
    response_time_ms = db.Column(db.Integer, default=0, nullable=False)
    final_url = db.Column(db.String(1024), nullable=True)
    ip_address = db.Column(db.String(128), nullable=True)

    total_endpoints = db.Column(db.Integer, default=0, nullable=False)
    total_technologies = db.Column(db.Integer, default=0, nullable=False)
    total_security_headers_missing = db.Column(db.Integer, default=0, nullable=False)

    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    duration_seconds = db.Column(db.Float, default=0.0, nullable=False)
    error_message = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    endpoints = db.relationship("DiscoveredEndpoint", backref="recon_scan", lazy="dynamic", cascade="all, delete-orphan")
    technologies = db.relationship("TechnologyFingerprint", backref="recon_scan", lazy="dynamic", cascade="all, delete-orphan")
    dns_records = db.relationship("DNSRecord", backref="recon_scan", lazy="dynamic", cascade="all, delete-orphan")
    security_headers = db.relationship("SecurityHeaderFinding", backref="recon_scan", lazy="dynamic", cascade="all, delete-orphan")
    metadata_record = db.relationship("WebsiteMetadata", backref="recon_scan", uselist=False, cascade="all, delete-orphan")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "target_id": self.target_id,
            "user_id": self.user_id,
            "status": self.status,
            "availability_status": self.availability_status,
            "http_status": self.http_status,
            "response_time_ms": self.response_time_ms,
            "final_url": self.final_url,
            "ip_address": self.ip_address,
            "total_endpoints": self.total_endpoints,
            "total_technologies": self.total_technologies,
            "total_security_headers_missing": self.total_security_headers_missing,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": round(self.duration_seconds, 2),
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class DiscoveredEndpoint(db.Model):
    __tablename__ = "discovered_endpoints"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("recon_scans.id", ondelete="CASCADE"), nullable=False, index=True)
    url = db.Column(db.String(1024), nullable=False)
    http_method = db.Column(db.String(10), default="GET", nullable=False)
    status_code = db.Column(db.Integer, nullable=True)
    content_type = db.Column(db.String(100), nullable=True)
    source = db.Column(db.String(50), default="html_link", nullable=False)  # html_link, form_action, script, robots_txt, sitemap_xml
    discovered_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "url": self.url,
            "http_method": self.http_method,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "source": self.source,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
        }


class TechnologyFingerprint(db.Model):
    __tablename__ = "technology_fingerprints"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("recon_scans.id", ondelete="CASCADE"), nullable=False, index=True)
    category = db.Column(db.String(50), nullable=False)  # server, framework, language, cms, js_library, cdn
    name = db.Column(db.String(120), nullable=False)
    version = db.Column(db.String(64), nullable=True)
    confidence = db.Column(db.String(20), default="MEDIUM", nullable=False)  # HIGH, MEDIUM, LOW
    evidence = db.Column(db.String(512), nullable=True)
    detected_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "category": self.category,
            "name": self.name,
            "version": self.version,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None,
        }


class DNSRecord(db.Model):
    __tablename__ = "dns_records"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("recon_scans.id", ondelete="CASCADE"), nullable=False, index=True)
    record_type = db.Column(db.String(16), nullable=False)  # A, AAAA, MX, NS, TXT, CNAME
    name = db.Column(db.String(255), nullable=False)
    value = db.Column(db.Text, nullable=False)
    ttl = db.Column(db.Integer, nullable=True)
    discovered_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "record_type": self.record_type,
            "name": self.name,
            "value": self.value,
            "ttl": self.ttl,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
        }


class SecurityHeaderFinding(db.Model):
    __tablename__ = "security_header_findings"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("recon_scans.id", ondelete="CASCADE"), nullable=False, index=True)
    header_name = db.Column(db.String(100), nullable=False)
    present = db.Column(db.Boolean, default=False, nullable=False)
    value = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(32), default="MISSING", nullable=False)  # OPTIMAL, SUBOPTIMAL, MISSING
    risk_level = db.Column(db.String(20), default="MEDIUM", nullable=False)  # INFO, LOW, MEDIUM, HIGH
    remediation = db.Column(db.Text, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "header_name": self.header_name,
            "present": self.present,
            "value": self.value,
            "status": self.status,
            "risk_level": self.risk_level,
            "remediation": self.remediation,
        }


class WebsiteMetadata(db.Model):
    __tablename__ = "website_metadata"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("recon_scans.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    title = db.Column(db.String(512), nullable=True)
    description = db.Column(db.Text, nullable=True)
    generator = db.Column(db.String(255), nullable=True)
    canonical_url = db.Column(db.String(1024), nullable=True)
    language = db.Column(db.String(32), nullable=True)
    open_graph_data = db.Column(db.Text, nullable=True)  # JSON-encoded dictionary

    def get_open_graph(self) -> dict:
        if not self.open_graph_data:
            return {}
        try:
            return json.loads(self.open_graph_data)
        except (ValueError, TypeError):
            return {}

    def set_open_graph(self, data: dict) -> None:
        self.open_graph_data = json.dumps(data) if data else "{}"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "title": self.title,
            "description": self.description,
            "generator": self.generator,
            "canonical_url": self.canonical_url,
            "language": self.language,
            "open_graph": self.get_open_graph(),
        }
