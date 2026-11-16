"""AppSentinel Security Analyst Orchestrator (V8).

High-level coordinator managing:
- Vulnerability finding security explanations and remediation blueprints.
- Target application posture assessment and risk summaries.
- Grounded, privacy-preserving conversational security chat.
- Context isolation, secret redaction, and prompt injection defenses.
- Structured schema validation and fallback engine routing.
- Audit logging (AIUsageLog), usage limits, and database persistence (AIAnalysis, AIConversation, AIMessage).
"""

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple, Dict, Any

from app.models import db
from app.models.vulnerability import Vulnerability, AIAnalysis
from app.models.ai import AIConversation, AIMessage, AIUsageLog
from app.ai.ai_config import AIConfig
from app.ai.prompt_manager import PromptManager
from app.ai.response_validator import ResponseValidator
from app.ai.fallback_engine import FallbackEngine
from app.ai.context_builder import ContextBuilder
from app.ai.ai_client import get_ai_client, AIProviderClient

logger = logging.getLogger(__name__)


class SecurityAnalyst:
    """Orchestrates defensive AI security operations with rigorous fallback and audit logging."""

    def __init__(self, ai_client: Optional[AIProviderClient] = None):
        self._ai_client = ai_client

    def _get_client(self) -> Optional[AIProviderClient]:
        if self._ai_client is not None:
            return self._ai_client
        return get_ai_client()

    @classmethod
    def check_daily_limit(cls, user_id: int, is_admin: bool = False) -> Tuple[bool, int, int]:
        """Check if user has reached their daily AI analysis limit.

        Returns:
            (is_allowed, current_count, max_limit)
        """
        max_limit = AIConfig.get_daily_limit()
        if is_admin:
            return True, 0, max_limit

        today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

        # Count successful or cloud requests today
        count = AIUsageLog.query.filter(
            AIUsageLog.user_id == user_id,
            AIUsageLog.created_at >= today_start,
            AIUsageLog.request_status.in_(["SUCCESS", "FALLBACK"]),
        ).count()

        return (count < max_limit), count, max_limit

    @classmethod
    def log_usage(
        cls,
        user_id: int,
        provider: str,
        model: str,
        analysis_type: str,
        input_tokens: int,
        output_tokens: int,
        status: str,
        error_message: Optional[str] = None,
    ) -> AIUsageLog:
        """Record token consumption and execution status for audit and billing."""
        clean_error = PromptManager.sanitize_untrusted_text(error_message, 1000) if error_message else None
        log = AIUsageLog(
            user_id=user_id,
            provider=provider,
            model=model,
            analysis_type=analysis_type,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            request_status=status,
            error_message=clean_error,
        )
        db.session.add(log)
        try:
            db.session.commit()
        except Exception as ex:
            db.session.rollback()
            logger.error("Failed to commit AIUsageLog: %s", ex)
        return log

    def analyze_vulnerability(
        self,
        finding_id: int,
        user_id: int,
        force_refresh: bool = False,
        is_admin: bool = False,
    ) -> Tuple[bool, Dict[str, Any], Optional[AIAnalysis], str]:
        """Generate structured security analysis for a specific vulnerability finding.

        Returns:
            (success, structured_result, analysis_record, message)
        """
        # 1. Authorization & Finding Retrieval
        finding_data = ContextBuilder.get_finding_context(finding_id, user_id, is_admin=is_admin)
        if not finding_data:
            return False, {}, None, "Finding not found or unauthorized access."

        # 2. Check existing analysis cache if not forced refresh
        if not force_refresh:
            existing = AIAnalysis.query.filter_by(vulnerability_id=finding_id).first()
            if existing and existing.structured_result:
                try:
                    cached_data = json.loads(existing.structured_result)
                    return True, cached_data, existing, "Loaded from analysis cache."
                except Exception:
                    pass

        # 3. Rate limit check
        allowed, count, limit = self.check_daily_limit(user_id, is_admin=is_admin)
        if not allowed:
            return False, {}, None, f"Daily AI request limit reached ({count}/{limit})."

        # 4. Construct prompt and check injection markers
        instructions, user_prompt, injection_detected = PromptManager.build_vulnerability_prompt(finding_data)

        # 5. Determine Provider & Execution Path
        client = self._get_client()
        result_data: Dict[str, Any] = {}
        is_fallback = True
        provider_name = FallbackEngine.PROVIDER_NAME
        model_name = FallbackEngine.MODEL_NAME
        tokens = {"input_tokens": 0, "output_tokens": 0}

        if client and AIConfig.is_enabled():
            success, raw_output, err_msg, tokens = client.generate_analysis(
                instructions=instructions,
                input_prompt=user_prompt,
            )

            if success and raw_output:
                valid, parsed_json, val_err = ResponseValidator.validate_analysis_response(raw_output)
                if valid and parsed_json:
                    result_data = parsed_json
                    is_fallback = False
                    provider_name = AIConfig.get_provider()
                    model_name = AIConfig.get_model()
                    self.log_usage(
                        user_id=user_id,
                        provider=provider_name,
                        model=model_name,
                        analysis_type="vulnerability_explanation",
                        input_tokens=tokens.get("input_tokens", 0),
                        output_tokens=tokens.get("output_tokens", 0),
                        status="SUCCESS",
                    )
                else:
                    logger.warning("AI output failed validation: %s. Falling back to deterministic engine.", val_err)
                    self.log_usage(
                        user_id=user_id,
                        provider=AIConfig.get_provider(),
                        model=AIConfig.get_model(),
                        analysis_type="vulnerability_explanation",
                        input_tokens=tokens.get("input_tokens", 0),
                        output_tokens=tokens.get("output_tokens", 0),
                        status="FALLBACK",
                        error_message=f"Schema validation failure: {val_err}",
                    )
            else:
                logger.warning("AI provider error: %s. Using deterministic fallback.", err_msg)
                self.log_usage(
                    user_id=user_id,
                    provider=AIConfig.get_provider(),
                    model=AIConfig.get_model(),
                    analysis_type="vulnerability_explanation",
                    input_tokens=0,
                    output_tokens=0,
                    status="FALLBACK",
                    error_message=err_msg,
                )

        if is_fallback:
            result_data = FallbackEngine.generate_vulnerability_analysis(finding_data)
            self.log_usage(
                user_id=user_id,
                provider=provider_name,
                model=model_name,
                analysis_type="vulnerability_explanation",
                input_tokens=0,
                output_tokens=0,
                status="FALLBACK" if AIConfig.is_enabled() else "DISABLED",
            )

        # 6. Save or Update AIAnalysis record
        analysis = AIAnalysis.query.filter_by(vulnerability_id=finding_id).first()
        if not analysis:
            analysis = AIAnalysis(
                vulnerability_id=finding_id,
                target_id=finding_data.get("target_id"),
                user_id=user_id,
            )
            db.session.add(analysis)

        analysis.target_id = finding_data.get("target_id")
        analysis.user_id = user_id
        analysis.analysis_type = "vulnerability_explanation"
        analysis.provider = provider_name
        analysis.model_name = model_name
        analysis.status = "COMPLETED"
        analysis.ai_confidence = result_data.get("ai_confidence", "MEDIUM")
        analysis.explanation = result_data.get("technical_explanation", "")
        analysis.potential_impact = result_data.get("impact", "")
        analysis.root_cause = result_data.get("root_cause", "")

        # Extract primary code example if present
        recs = result_data.get("recommendations", [])
        code_snippets = [r.get("code_example") for r in recs if r.get("code_example")]
        analysis.secure_coding_example = code_snippets[0] if code_snippets else ""
        analysis.recommended_remediation = "\n\n".join(
            [f"**[{r.get('priority', 'Action')}] {r.get('action', '')}**\n{r.get('details', '')}" for r in recs]
        )
        analysis.verification_steps = "\n".join(result_data.get("verification_steps", []))
        analysis.evidence_assessment = result_data.get("evidence_assessment", "")
        analysis.evidence_limitations = "\n".join(result_data.get("limitations", []))
        analysis.structured_result = json.dumps(result_data)
        analysis.is_fallback = is_fallback

        try:
            db.session.commit()
        except Exception as ex:
            db.session.rollback()
            logger.error("Failed to commit AIAnalysis: %s", ex)

        msg = "Analysis generated via deterministic fallback engine." if is_fallback else f"Analysis completed via {provider_name} ({model_name})."
        return True, result_data, analysis, msg

    def analyze_target(
        self,
        target_id: int,
        user_id: int,
        is_admin: bool = False,
    ) -> Tuple[bool, Dict[str, Any], str]:
        """Generate posture assessment and executive summary for a target."""
        target_data = ContextBuilder.get_target_context(target_id, user_id, is_admin=is_admin)
        if not target_data:
            return False, {}, "Target not found or unauthorized access."

        allowed, count, limit = self.check_daily_limit(user_id, is_admin=is_admin)
        if not allowed:
            return False, {}, f"Daily AI request limit reached ({count}/{limit})."

        instructions, user_prompt, _ = PromptManager.build_target_summary_prompt(target_data)
        client = self._get_client()

        result_data: Dict[str, Any] = {}
        is_fallback = True
        provider_name = FallbackEngine.PROVIDER_NAME
        model_name = FallbackEngine.MODEL_NAME

        if client and AIConfig.is_enabled():
            success, raw_output, err_msg, tokens = client.generate_analysis(
                instructions=instructions,
                input_prompt=user_prompt,
            )
            if success and raw_output:
                valid, parsed_json, val_err = ResponseValidator.validate_analysis_response(raw_output)
                if valid and parsed_json:
                    result_data = parsed_json
                    is_fallback = False
                    provider_name = AIConfig.get_provider()
                    model_name = AIConfig.get_model()
                    self.log_usage(
                        user_id=user_id,
                        provider=provider_name,
                        model=model_name,
                        analysis_type="target_summary",
                        input_tokens=tokens.get("input_tokens", 0),
                        output_tokens=tokens.get("output_tokens", 0),
                        status="SUCCESS",
                    )
                else:
                    self.log_usage(
                        user_id=user_id,
                        provider=AIConfig.get_provider(),
                        model=AIConfig.get_model(),
                        analysis_type="target_summary",
                        input_tokens=tokens.get("input_tokens", 0),
                        output_tokens=tokens.get("output_tokens", 0),
                        status="FALLBACK",
                        error_message=f"Validation failure: {val_err}",
                    )
            else:
                self.log_usage(
                    user_id=user_id,
                    provider=AIConfig.get_provider(),
                    model=AIConfig.get_model(),
                    analysis_type="target_summary",
                    input_tokens=0,
                    output_tokens=0,
                    status="FALLBACK",
                    error_message=err_msg,
                )

        if is_fallback:
            result_data = FallbackEngine.generate_target_summary(target_data)
            self.log_usage(
                user_id=user_id,
                provider=provider_name,
                model=model_name,
                analysis_type="target_summary",
                input_tokens=0,
                output_tokens=0,
                status="FALLBACK" if AIConfig.is_enabled() else "DISABLED",
            )

        msg = "Target assessment generated via deterministic engine." if is_fallback else f"Target assessment generated via {provider_name}."
        return True, result_data, msg

    def process_chat_query(
        self,
        user_id: int,
        user_query: str,
        target_id: Optional[int] = None,
        conversation_id: Optional[int] = None,
        is_admin: bool = False,
    ) -> Tuple[bool, Dict[str, Any], Optional[AIConversation], Optional[AIMessage], str]:
        """Process conversational security inquiry grounded in authorized records."""
        if not user_query or not user_query.strip():
            return False, {}, None, None, "User query cannot be empty."

        # Verify target access if specified
        if target_id and not ContextBuilder.check_target_access(target_id, user_id, is_admin=is_admin):
            return False, {}, None, None, "Unauthorized target scope."

        allowed, count, limit = self.check_daily_limit(user_id, is_admin=is_admin)
        if not allowed:
            return False, {}, None, None, f"Daily AI request limit reached ({count}/{limit})."

        # Resolve or create conversation
        conversation = None
        if conversation_id:
            conversation = AIConversation.query.filter_by(id=conversation_id).first()
            if not conversation or (not is_admin and conversation.user_id != user_id):
                return False, {}, None, None, "Conversation not found or unauthorized access."

        if not conversation:
            clean_title = (user_query[:40] + "...") if len(user_query) > 40 else user_query
            conversation = AIConversation(
                user_id=user_id,
                target_id=target_id,
                title=clean_title,
            )
            db.session.add(conversation)
            db.session.flush()

        # Add user message
        user_msg = AIMessage(
            conversation_id=conversation.id,
            role="user",
            content=user_query,
            is_fallback=False,
        )
        db.session.add(user_msg)

        # Build context
        authorized_context = ContextBuilder.get_chat_context(user_id, target_id=target_id, is_admin=is_admin)

        # Retrieve prior conversation turns
        prior_messages = (
            AIMessage.query.filter_by(conversation_id=conversation.id)
            .order_by(AIMessage.id.asc())
            .limit(10)
            .all()
        )
        history = [{"role": m.role, "content": m.content} for m in prior_messages]

        instructions, prompt_body, injection_detected = PromptManager.build_chat_prompt(
            user_query=user_query,
            authorized_context=authorized_context,
            conversation_history=history,
        )

        client = self._get_client()
        result_data: Dict[str, Any] = {}
        is_fallback = True
        provider_name = FallbackEngine.PROVIDER_NAME
        model_name = FallbackEngine.MODEL_NAME

        if client and AIConfig.is_enabled():
            success, raw_output, err_msg, tokens = client.generate_analysis(
                instructions=instructions,
                input_prompt=prompt_body,
            )
            if success and raw_output:
                valid, parsed_json, val_err = ResponseValidator.validate_analysis_response(raw_output)
                if valid and parsed_json:
                    result_data = parsed_json
                    is_fallback = False
                    provider_name = AIConfig.get_provider()
                    model_name = AIConfig.get_model()
                    self.log_usage(
                        user_id=user_id,
                        provider=provider_name,
                        model=model_name,
                        analysis_type="security_chat",
                        input_tokens=tokens.get("input_tokens", 0),
                        output_tokens=tokens.get("output_tokens", 0),
                        status="SUCCESS",
                    )
                else:
                    self.log_usage(
                        user_id=user_id,
                        provider=AIConfig.get_provider(),
                        model=AIConfig.get_model(),
                        analysis_type="security_chat",
                        input_tokens=tokens.get("input_tokens", 0),
                        output_tokens=tokens.get("output_tokens", 0),
                        status="FALLBACK",
                        error_message=f"Validation failure: {val_err}",
                    )
            else:
                self.log_usage(
                    user_id=user_id,
                    provider=AIConfig.get_provider(),
                    model=AIConfig.get_model(),
                    analysis_type="security_chat",
                    input_tokens=0,
                    output_tokens=0,
                    status="FALLBACK",
                    error_message=err_msg,
                )

        if is_fallback:
            target_data = ContextBuilder.get_target_context(target_id, user_id, is_admin=is_admin) if target_id else None
            result_data = FallbackEngine.generate_chat_response(user_query, target_data=target_data)
            self.log_usage(
                user_id=user_id,
                provider=provider_name,
                model=model_name,
                analysis_type="security_chat",
                input_tokens=0,
                output_tokens=0,
                status="FALLBACK" if AIConfig.is_enabled() else "DISABLED",
            )

        # Store assistant response message
        assistant_text = result_data.get("summary", "")
        if result_data.get("technical_explanation"):
            assistant_text += "\n\n" + result_data.get("technical_explanation")

        assistant_msg = AIMessage(
            conversation_id=conversation.id,
            role="assistant",
            content=assistant_text,
            is_fallback=is_fallback,
        )
        db.session.add(assistant_msg)
        conversation.updated_at = datetime.now(timezone.utc)

        try:
            db.session.commit()
        except Exception as ex:
            db.session.rollback()
            logger.error("Failed to commit chat turn: %s", ex)

        msg = "Response served by deterministic engine." if is_fallback else f"Response served by {provider_name}."
        return True, result_data, conversation, assistant_msg, msg
