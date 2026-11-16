from datetime import datetime, timezone
import secrets
from urllib.parse import urlparse
from . import db


class Target(db.Model):
    __tablename__ = "targets"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    target_url = db.Column(db.String(512), nullable=False, index=True)
    domain = db.Column(db.String(255), nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    verification_token = db.Column(db.String(64), nullable=False, unique=True, default=lambda: secrets.token_hex(32))
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    verification_method = db.Column(db.String(32), default="manual", nullable=False)
    verified_at = db.Column(db.DateTime, nullable=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    scans = db.relationship("Scan", backref="target", lazy="dynamic", cascade="all, delete-orphan")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if self.target_url and not self.domain:
            parsed = urlparse(self.target_url)
            self.domain = parsed.netloc.split(":")[0].lower() if parsed.netloc else ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "target_url": self.target_url,
            "domain": self.domain,
            "description": self.description,
            "is_verified": self.is_verified,
            "verification_token": self.verification_token,
            "owner_id": self.owner_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
        }

    def __repr__(self) -> str:
        return f"<Target id={self.id} domain='{self.domain}' verified={self.is_verified}>"
