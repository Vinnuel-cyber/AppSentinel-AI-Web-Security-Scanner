"""AppSentinel AI Security Analyst Database Models (V8).

Defines persistent models for:
- AIConversation: Natural-language security Q&A conversation thread.
- AIMessage: Individual message turn within an AI conversation.
- AIUsageLog: Audit log tracking token consumption, latency, and provider status.
"""

from datetime import datetime, timezone
from app.models import db


class AIConversation(db.Model):
    """Represents a scoped natural-language analyst chat session."""
    __tablename__ = "ai_conversations"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id", ondelete="SET NULL"), nullable=True, index=True)

    title = db.Column(db.String(255), default="Security Analysis Session", nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    messages = db.relationship("AIMessage", backref="conversation", lazy="dynamic", cascade="all, delete-orphan", order_by="AIMessage.id.asc()")
    target = db.relationship("Target", foreign_keys=[target_id])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "target_id": self.target_id,
            "target_name": self.target.name if self.target else None,
            "title": self.title,
            "message_count": self.messages.count(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class AIMessage(db.Model):
    """Represents an individual message turn in an AI conversation."""
    __tablename__ = "ai_messages"

    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey("ai_conversations.id", ondelete="CASCADE"), nullable=False, index=True)

    role = db.Column(db.String(20), nullable=False)  # "user", "assistant", "system"
    content = db.Column(db.Text, nullable=False)
    is_fallback = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "conversation_id": self.conversation_id,
            "role": self.role,
            "content": self.content,
            "is_fallback": self.is_fallback,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AIUsageLog(db.Model):
    """Audit log tracking token consumption, request latency, and billing limits."""
    __tablename__ = "ai_usage_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    provider = db.Column(db.String(50), nullable=False)
    model = db.Column(db.String(64), nullable=False)
    analysis_type = db.Column(db.String(64), nullable=False)  # "vulnerability_explanation", "target_summary", "security_chat"

    input_tokens = db.Column(db.Integer, default=0, nullable=False)
    output_tokens = db.Column(db.Integer, default=0, nullable=False)
    request_status = db.Column(db.String(30), default="SUCCESS", nullable=False)  # SUCCESS, FAILED, RATE_LIMITED, FALLBACK, DISABLED
    error_message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "provider": self.provider,
            "model": self.model,
            "analysis_type": self.analysis_type,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.input_tokens + self.output_tokens,
            "request_status": self.request_status,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
