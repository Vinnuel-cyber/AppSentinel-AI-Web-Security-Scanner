"""AppSentinel AI Security Analyst Blueprint (V8).

Routes for:
- AI Security Analyst Dashboard & Interactive Workbench.
- Vulnerability Finding Deep Diagnostic Analysis.
- Target Posture Assessment & Risk Synthesis.
- Grounded Natural-Language Security Chat.
- Conversation Management and Status Endpoints.
"""

from flask import (
    Blueprint,
    render_template,
    request,
    jsonify,
    abort,
    flash,
    redirect,
    url_for,
    current_app,
)
from flask_login import login_required, current_user
from app.models import db, Target, Vulnerability, Scan
from app.models.vulnerability import AIAnalysis
from app.models.ai import AIConversation, AIMessage, AIUsageLog
from app.ai.ai_service import AIService
from app.ai.context_builder import ContextBuilder

ai_bp = Blueprint("ai", __name__, url_prefix="/ai")


@ai_bp.route("", methods=["GET"])
@ai_bp.route("/", methods=["GET"])
@login_required
def index():
    """AI Security Analyst SOC dashboard view."""
    is_admin = current_user.role == "ADMIN"

    # Fetch user's authorized targets
    if is_admin:
        targets = Target.query.filter_by(is_active=True).all()
        target_ids = [t.id for t in targets]
        recent_analyses = AIAnalysis.query.order_by(AIAnalysis.created_at.desc()).limit(10).all()
        recent_findings = Vulnerability.query.order_by(Vulnerability.cvss_score.desc()).limit(15).all()
    else:
        targets = Target.query.filter_by(owner_id=current_user.id, is_active=True).all()
        target_ids = [t.id for t in targets]
        recent_analyses = (
            AIAnalysis.query.filter_by(user_id=current_user.id)
            .order_by(AIAnalysis.created_at.desc())
            .limit(10)
            .all()
        )
        recent_findings = (
            Vulnerability.query.filter(
                (Vulnerability.target_id.in_(target_ids))
                | (
                    Vulnerability.scan_id.in_(
                        db.session.query(Scan.id).filter(Scan.target_id.in_(target_ids))
                    )
                )
            )
            .order_by(Vulnerability.cvss_score.desc())
            .limit(15)
            .all()
            if target_ids
            else []
        )

    status = AIService.get_status()
    conversations = AIService.get_user_conversations(current_user.id, limit=10)

    return render_template(
        "ai/index.html",
        targets=targets,
        recent_analyses=recent_analyses,
        recent_findings=recent_findings,
        ai_status=status,
        conversations=conversations,
    )


@ai_bp.route("/analyst", methods=["GET"])
@login_required
def analyst_workbench():
    """Dedicated interactive AI security analyst console and chat workbench."""
    is_admin = current_user.role == "ADMIN"
    if is_admin:
        targets = Target.query.filter_by(is_active=True).all()
    else:
        targets = Target.query.filter_by(owner_id=current_user.id, is_active=True).all()

    status = AIService.get_status()
    conversations = AIService.get_user_conversations(current_user.id, limit=20)

    return render_template(
        "ai/analyst.html",
        targets=targets,
        ai_status=status,
        conversations=conversations,
    )


@ai_bp.route("/status", methods=["GET"])
@login_required
def status():
    """Return JSON health and availability status of the AI engine."""
    return jsonify(AIService.get_status())


@ai_bp.route("/analyze/finding/<int:finding_id>", methods=["POST"])
@login_required
def analyze_finding(finding_id: int):
    """Run AI root-cause analysis and remediation on a specific vulnerability finding."""
    is_admin = current_user.role == "ADMIN"

    # Check access
    if not ContextBuilder.check_finding_access(finding_id, current_user.id, is_admin=is_admin):
        return jsonify({"error": "Forbidden", "message": "Finding not found or unauthorized access."}), 403

    force_refresh = False
    if request.is_json:
        force_refresh = bool(request.json.get("force_refresh", False))
    elif request.form:
        force_refresh = request.form.get("force_refresh", "false").lower() in ("true", "1")

    service = AIService()
    success, result_data, analysis, msg = service.analyze_finding(
        finding_id=finding_id,
        user_id=current_user.id,
        force_refresh=force_refresh,
        is_admin=is_admin,
    )

    if not success:
        return jsonify({"error": "Analysis failed", "message": msg}), 400

    return jsonify({
        "success": True,
        "message": msg,
        "analysis_id": analysis.id if analysis else None,
        "data": result_data,
    })


@ai_bp.route("/analyze/target/<int:target_id>", methods=["POST"])
@login_required
def analyze_target(target_id: int):
    """Run AI security posture assessment and executive summary for a target."""
    is_admin = current_user.role == "ADMIN"

    if not ContextBuilder.check_target_access(target_id, current_user.id, is_admin=is_admin):
        return jsonify({"error": "Forbidden", "message": "Target not found or unauthorized access."}), 403

    service = AIService()
    success, result_data, msg = service.analyze_target(
        target_id=target_id,
        user_id=current_user.id,
        is_admin=is_admin,
    )

    if not success:
        return jsonify({"error": "Target analysis failed", "message": msg}), 400

    return jsonify({
        "success": True,
        "message": msg,
        "data": result_data,
    })


@ai_bp.route("/analysis/<int:analysis_id>", methods=["GET"])
@login_required
def get_analysis_detail(analysis_id: int):
    """Retrieve full analysis report by ID."""
    is_admin = current_user.role == "ADMIN"
    analysis = AIService.get_analysis_by_id(analysis_id, current_user.id, is_admin=is_admin)

    if not analysis:
        return jsonify({"error": "Not Found", "message": "Analysis record not found or unauthorized."}), 404

    # If JSON requested, return data directly
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({
            "success": True,
            "analysis": analysis.to_dict(),
        })

    # Render HTML template view
    finding = Vulnerability.query.filter_by(id=analysis.vulnerability_id).first()
    return render_template(
        "ai/analysis_detail.html",
        analysis=analysis,
        finding=finding,
        structured=analysis.to_dict().get("structured_result"),
    )


@ai_bp.route("/chat", methods=["POST"])
@login_required
def chat():
    """Handle conversational security questions grounded in authorized scan results."""
    data = request.get_json(silent=True) or request.form or {}
    query = (data.get("query") or data.get("message") or "").strip()

    if not query:
        return jsonify({"error": "Bad Request", "message": "Query message cannot be empty."}), 400

    target_id = data.get("target_id")
    if target_id:
        try:
            target_id = int(target_id)
        except (ValueError, TypeError):
            target_id = None

    conversation_id = data.get("conversation_id")
    if conversation_id:
        try:
            conversation_id = int(conversation_id)
        except (ValueError, TypeError):
            conversation_id = None

    is_admin = current_user.role == "ADMIN"
    service = AIService()

    success, result_data, conversation, assistant_msg, msg = service.send_chat_message(
        user_id=current_user.id,
        query=query,
        target_id=target_id,
        conversation_id=conversation_id,
        is_admin=is_admin,
    )

    if not success:
        return jsonify({"error": "Chat failed", "message": msg}), 400

    return jsonify({
        "success": True,
        "message": msg,
        "conversation_id": conversation.id if conversation else None,
        "assistant_message_id": assistant_msg.id if assistant_msg else None,
        "data": result_data,
    })


@ai_bp.route("/conversations", methods=["GET"])
@login_required
def list_conversations():
    """List recent conversation sessions for the active user."""
    convs = AIService.get_user_conversations(current_user.id)
    return jsonify({"success": True, "conversations": convs})


@ai_bp.route("/conversation/<int:conversation_id>", methods=["GET"])
@login_required
def get_conversation(conversation_id: int):
    """Retrieve message transcript for a specific conversation."""
    is_admin = current_user.role == "ADMIN"
    messages = AIService.get_conversation_messages(conversation_id, current_user.id, is_admin=is_admin)

    if messages is None:
        return jsonify({"error": "Not Found", "message": "Conversation not found or unauthorized."}), 404

    return jsonify({"success": True, "messages": messages})


@ai_bp.route("/conversation/<int:conversation_id>", methods=["DELETE"])
@login_required
def delete_conversation(conversation_id: int):
    """Delete an authorized conversation thread."""
    is_admin = current_user.role == "ADMIN"
    deleted = AIService.delete_conversation(conversation_id, current_user.id, is_admin=is_admin)

    if not deleted:
        return jsonify({"error": "Not Found", "message": "Conversation not found or unauthorized."}), 404

    return jsonify({"success": True, "message": "Conversation deleted successfully."})
