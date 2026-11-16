"""AppSentinel AI Service Facade (V8).

Service layer decoupling HTTP route controllers from lower-level AI engines,
orchestration pipelines, and database transactions.
"""

from typing import Optional, Dict, Any, List, Tuple

from app.models import db
from app.models.vulnerability import AIAnalysis, Vulnerability
from app.models.ai import AIConversation, AIMessage
from app.ai.ai_config import AIConfig
from app.ai.security_analyst import SecurityAnalyst
from app.ai.context_builder import ContextBuilder


class AIService:
    """Service providing unified AI capabilities for web views and API endpoints."""

    def __init__(self, analyst: Optional[SecurityAnalyst] = None):
        self.analyst = analyst or SecurityAnalyst()

    @classmethod
    def get_status(cls) -> Dict[str, Any]:
        """Return the current AI system status, provider details, and limits."""
        return {
            "ai_enabled": AIConfig.is_enabled(),
            "provider": AIConfig.get_provider(),
            "model": AIConfig.get_model(),
            "timeout_seconds": AIConfig.get_timeout(),
            "max_output_tokens": AIConfig.get_max_output_tokens(),
            "daily_limit_per_user": AIConfig.get_daily_limit(),
            "has_api_key": bool(AIConfig.get_api_key()),
            "fallback_engine": "deterministic-v8",
        }

    def analyze_finding(
        self,
        finding_id: int,
        user_id: int,
        force_refresh: bool = False,
        is_admin: bool = False,
    ) -> Tuple[bool, Dict[str, Any], Optional[AIAnalysis], str]:
        """Analyze a specific finding with ownership validation."""
        return self.analyst.analyze_vulnerability(
            finding_id=finding_id,
            user_id=user_id,
            force_refresh=force_refresh,
            is_admin=is_admin,
        )

    def analyze_target(
        self,
        target_id: int,
        user_id: int,
        is_admin: bool = False,
    ) -> Tuple[bool, Dict[str, Any], str]:
        """Analyze a target application posture with ownership validation."""
        return self.analyst.analyze_target(
            target_id=target_id,
            user_id=user_id,
            is_admin=is_admin,
        )

    def send_chat_message(
        self,
        user_id: int,
        query: str,
        target_id: Optional[int] = None,
        conversation_id: Optional[int] = None,
        is_admin: bool = False,
    ) -> Tuple[bool, Dict[str, Any], Optional[AIConversation], Optional[AIMessage], str]:
        """Send a security inquiry to the analyst assistant."""
        return self.analyst.process_chat_query(
            user_id=user_id,
            user_query=query,
            target_id=target_id,
            conversation_id=conversation_id,
            is_admin=is_admin,
        )

    @classmethod
    def get_user_conversations(cls, user_id: int, limit: int = 20) -> List[Dict[str, Any]]:
        """List chat sessions belonging to a specific user."""
        convs = (
            AIConversation.query.filter_by(user_id=user_id)
            .order_by(AIConversation.updated_at.desc())
            .limit(limit)
            .all()
        )
        return [c.to_dict() for c in convs]

    @classmethod
    def get_conversation_messages(
        cls, conversation_id: int, user_id: int, is_admin: bool = False
    ) -> Optional[List[Dict[str, Any]]]:
        """Retrieve message history for an authorized conversation."""
        conv = AIConversation.query.filter_by(id=conversation_id).first()
        if not conv or (not is_admin and conv.user_id != user_id):
            return None

        msgs = conv.messages.order_by(AIMessage.id.asc()).all()
        return [m.to_dict() for m in msgs]

    @classmethod
    def delete_conversation(
        cls, conversation_id: int, user_id: int, is_admin: bool = False
    ) -> bool:
        """Delete an authorized conversation thread."""
        conv = AIConversation.query.filter_by(id=conversation_id).first()
        if not conv or (not is_admin and conv.user_id != user_id):
            return False

        db.session.delete(conv)
        try:
            db.session.commit()
            return True
        except Exception:
            db.session.rollback()
            return False

    @classmethod
    def get_analysis_by_id(
        cls, analysis_id: int, user_id: int, is_admin: bool = False
    ) -> Optional[AIAnalysis]:
        """Retrieve an AIAnalysis record if user is authorized."""
        analysis = AIAnalysis.query.filter_by(id=analysis_id).first()
        if not analysis:
            return None

        if is_admin:
            return analysis

        if analysis.vulnerability_id:
            if ContextBuilder.check_finding_access(analysis.vulnerability_id, user_id, is_admin=False):
                return analysis
            return None

        if analysis.target_id:
            if ContextBuilder.check_target_access(analysis.target_id, user_id, is_admin=False):
                return analysis
            return None

        return analysis if analysis.user_id == user_id else None

    @classmethod
    def get_analysis_for_finding(
        cls, finding_id: int, user_id: int, is_admin: bool = False
    ) -> Optional[AIAnalysis]:
        """Retrieve the existing AIAnalysis record for a specific finding."""
        if not ContextBuilder.check_finding_access(finding_id, user_id, is_admin=is_admin):
            return None
        return AIAnalysis.query.filter_by(vulnerability_id=finding_id).first()
