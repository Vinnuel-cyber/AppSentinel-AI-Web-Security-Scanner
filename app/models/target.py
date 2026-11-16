from datetime import datetime, timezone, timedelta
import secrets
import hashlib
from urllib.parse import urlparse
from . import db


class Target(db.Model):
    __tablename__ = "targets"

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    target_url = db.Column(db.String(512), nullable=False, index=True)
    domain = db.Column(db.String(255), nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    environment = db.Column(db.String(32), default="Production", nullable=False)  # Development, Staging, Production
    
    # Ownership & Verification Fields
    verification_token = db.Column(db.String(64), nullable=False, unique=True, default=lambda: secrets.token_hex(32))
    verification_token_hash = db.Column(db.String(64), nullable=True)
    verification_status = db.Column(db.String(32), default="PENDING_VERIFICATION", nullable=False, index=True)  # PENDING_VERIFICATION, VERIFIED, FAILED, EXPIRED
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    verification_method = db.Column(db.String(32), default="manual", nullable=False)  # dns_txt, http_well_known, manual
    verification_expires_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc) + timedelta(days=7), nullable=False)
    verified_at = db.Column(db.DateTime, nullable=True)
    
    # Soft deletion & state
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    deleted_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Backward compatibility synonyms / properties
    @property
    def user_id(self):
        return self.owner_id

    @user_id.setter
    def user_id(self, val):
        self.owner_id = val

    @property
    def url(self):
        return self.target_url

    @url.setter
    def url(self, val):
        self.target_url = val

    @property
    def normalized_domain(self):
        return self.domain

    @normalized_domain.setter
    def normalized_domain(self, val):
        self.domain = val

    # Relationships
    scans = db.relationship("Scan", backref="target", lazy="dynamic", cascade="all, delete-orphan")
    audit_logs = db.relationship("TargetAuditLog", backref="target", lazy="dynamic", cascade="all, delete-orphan")

    def __init__(self, **kwargs):
        # Support user_id and url aliases during initialization
        if "user_id" in kwargs and "owner_id" not in kwargs:
            kwargs["owner_id"] = kwargs.pop("user_id")
        if "url" in kwargs and "target_url" not in kwargs:
            kwargs["target_url"] = kwargs.pop("url")
        if "normalized_domain" in kwargs and "domain" not in kwargs:
            kwargs["domain"] = kwargs.pop("normalized_domain")

        super().__init__(**kwargs)
        if self.target_url and not self.domain:
            parsed = urlparse(self.target_url)
            self.domain = parsed.hostname.lower() if parsed.hostname else ""
            
        if self.verification_token and not self.verification_token_hash:
            self.verification_token_hash = hashlib.sha256(self.verification_token.encode()).hexdigest()
        if not self.verification_expires_at:
            self.verification_expires_at = datetime.now(timezone.utc) + timedelta(days=7)

    def is_token_expired(self) -> bool:
        if not self.verification_expires_at:
            return True
        now = datetime.now(timezone.utc)
        expires = self.verification_expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return now > expires

    def regenerate_verification_token(self) -> str:
        """Regenerate verification token and reset verified status."""
        new_token = secrets.token_hex(32)
        self.verification_token = new_token
        self.verification_token_hash = hashlib.sha256(new_token.encode()).hexdigest()
        self.verification_expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        self.is_verified = False
        self.verification_status = "PENDING_VERIFICATION"
        self.verified_at = None
        db.session.commit()
        return new_token

    def mark_verified(self, method: str) -> None:
        """Mark target as verified and record method/time."""
        self.is_verified = True
        self.verification_status = "VERIFIED"
        self.verification_method = method
        self.verified_at = datetime.now(timezone.utc)
        db.session.commit()

    def soft_delete(self) -> None:
        """Mark target as deleted while preserving historical scan evidence."""
        self.is_active = False
        self.deleted_at = datetime.now(timezone.utc)
        db.session.commit()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "target_url": self.target_url,
            "url": self.target_url,
            "domain": self.domain,
            "normalized_domain": self.domain,
            "description": self.description,
            "environment": self.environment,
            "is_verified": self.is_verified,
            "verification_status": self.verification_status,
            "verification_method": self.verification_method,
            "verification_token": self.verification_token,
            "verification_expires_at": self.verification_expires_at.isoformat() if self.verification_expires_at else None,
            "owner_id": self.owner_id,
            "user_id": self.owner_id,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "deleted_at": self.deleted_at.isoformat() if self.deleted_at else None,
        }

    def __repr__(self) -> str:
        return f"<Target id={self.id} domain='{self.domain}' status='{self.verification_status}'>"


class TargetAuditLog(db.Model):
    __tablename__ = "target_audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    action = db.Column(db.String(64), nullable=False)  # CREATED, UPDATED, DELETED, VERIFY_REQUESTED, VERIFY_SUCCESS, VERIFY_FAILED
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "target_id": self.target_id,
            "user_id": self.user_id,
            "action": self.action,
            "details": self.details,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
