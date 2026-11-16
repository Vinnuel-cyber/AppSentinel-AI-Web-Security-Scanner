import re
from datetime import datetime, timezone
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from . import db

PASSWORD_REGEX = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^~_\-+=<>.,:;])[A-Za-z\d@$!%*?&#^~_\-+=<>.,:;]{8,}$")


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="USER", nullable=False)  # ADMIN, USER
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime, nullable=True)

    # Relationships
    targets = db.relationship("Target", backref="owner", lazy="dynamic", cascade="all, delete-orphan")
    scans = db.relationship("Scan", backref="user", lazy="dynamic", cascade="all, delete-orphan")

    @staticmethod
    def validate_password_strength(password: str) -> tuple[bool, str]:
        """Verify password complies with security baseline."""
        if not password or len(password) < 8:
            return False, "Password must be at least 8 characters long."
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter."
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter."
        if not re.search(r"\d", password):
            return False, "Password must contain at least one digit."
        if not re.search(r"[@$!%*?&#^~_\-+=<>.,:;]", password):
            return False, "Password must contain at least one special character."
        return True, ""

    def set_password(self, password: str, enforce_complexity: bool = False) -> None:
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if enforce_complexity:
            valid, err = self.validate_password_strength(password)
            if not valid:
                raise ValueError(err)
        self.password_hash = generate_password_hash(password, method="scrypt")

    def check_password(self, password: str) -> bool:
        if not self.password_hash or not password:
            return False
        return check_password_hash(self.password_hash, password)

    def is_admin(self) -> bool:
        return (self.role or "").upper() == "ADMIN"

    def record_login(self) -> None:
        self.last_login = datetime.now(timezone.utc)
        db.session.commit()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "full_name": self.full_name,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }

    def __repr__(self) -> str:
        return f"<User id={self.id} username='{self.username}' role='{self.role}'>"
