from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    jsonify,
    current_app,
    abort,
)
from flask_login import login_required, current_user
from app.models import (
    db,
    Target,
    Vulnerability,
    OWASPAssessment,
    OWASPFindingMapping,
)
from app.services.owasp_service import OWASPService, OWASPServiceError
from app.security.owasp_mapper import OWASPMapper

owasp_bp = Blueprint("owasp", __name__, url_prefix="/owasp")


@owasp_bp.route("", methods=["GET"])
@login_required
def index():
    """OWASP Top 10 Security Assessment Dashboard."""
    if current_user.role == "ADMIN":
        targets = Target.query.filter_by(is_active=True).order_by(Target.name.asc()).all()
        assessments = OWASPAssessment.query.order_by(OWASPAssessment.created_at.desc()).limit(20).all()
        mappings_query = OWASPFindingMapping.query
    else:
        targets = Target.query.filter_by(owner_id=current_user.id, is_active=True).order_by(Target.name.asc()).all()
        assessments = OWASPAssessment.query.filter_by(user_id=current_user.id).order_by(OWASPAssessment.created_at.desc()).limit(20).all()
        mappings_query = OWASPFindingMapping.query.join(Vulnerability).join(Target, Vulnerability.target_id == Target.id).filter(Target.owner_id == current_user.id)

    verified_targets = [t for t in targets if t.is_verified and t.verification_status == "VERIFIED"]

    # Compute category distribution
    all_mappings = mappings_query.all()
    category_counts = {cat_code: 0 for cat_code in OWASPMapper.CATEGORIES.keys()}
    for m in all_mappings:
        if m.primary_category_code in category_counts:
            category_counts[m.primary_category_code] += 1

    confidence_counts = {
        "HIGH": sum(1 for m in all_mappings if m.confidence == "HIGH"),
        "MEDIUM": sum(1 for m in all_mappings if m.confidence == "MEDIUM"),
        "LOW": sum(1 for m in all_mappings if m.confidence == "LOW"),
    }

    return render_template(
        "owasp/dashboard.html",
        targets=targets,
        verified_targets=verified_targets,
        assessments=assessments,
        total_mappings=len(all_mappings),
        category_counts=category_counts,
        category_definitions=OWASPMapper.CATEGORIES,
        confidence_counts=confidence_counts,
        framework_version=OWASPMapper.FRAMEWORK_VERSION,
    )


@owasp_bp.route("/assessment/<int:target_id>", methods=["GET"])
@login_required
def target_assessment(target_id: int):
    """View detailed OWASP Top 10 assessment for an authorized target."""
    target = db.session.get(Target, target_id)
    if not target or not target.is_active:
        abort(404)

    # RBAC / Ownership enforcement
    if current_user.role != "ADMIN" and target.owner_id != current_user.id:
        abort(403)

    latest_assessment = (
        OWASPAssessment.query.filter_by(target_id=target.id)
        .order_by(OWASPAssessment.created_at.desc())
        .first()
    )

    # Fetch all mappings for this target's vulnerabilities
    mappings = (
        OWASPFindingMapping.query.join(Vulnerability)
        .filter(Vulnerability.target_id == target.id)
        .order_by(OWASPFindingMapping.primary_category_code.asc())
        .all()
    )

    return render_template(
        "owasp/assessment.html",
        target=target,
        assessment=latest_assessment,
        mappings=mappings,
        category_definitions=OWASPMapper.CATEGORIES,
    )


@owasp_bp.route("/analyze/<int:target_id>", methods=["POST"])
@login_required
def analyze_target(target_id: int):
    """Trigger an OWASP Top 10 and Risk Assessment for a verified target."""
    target = db.session.get(Target, target_id)
    if not target or not target.is_active:
        if request.is_json:
            return jsonify({"error": "Target not found or inactive."}), 404
        flash("Target not found or inactive.", "danger")
        return redirect(url_for("owasp.index"))

    try:
        OWASPService.validate_target_access(target, current_user)
    except OWASPServiceError as err:
        if request.is_json:
            return jsonify({"error": str(err)}), 403
        flash(str(err), "danger")
        return redirect(url_for("owasp.index"))

    try:
        assessment = OWASPService.run_target_assessment(target.id, current_user.id)
        if request.is_json:
            return jsonify({
                "message": "OWASP assessment completed successfully.",
                "assessment_id": assessment.id,
                "total_findings_mapped": assessment.total_findings_mapped,
                "top_category": assessment.top_category,
                "summary": assessment.get_summary(),
            }), 201
        flash(f"OWASP Top 10 Assessment completed ({assessment.total_findings_mapped} findings mapped).", "success")
        return redirect(url_for("owasp.target_assessment", target_id=target.id))
    except Exception as exc:
        current_app.logger.error("OWASP assessment failed: %s", exc)
        if request.is_json:
            return jsonify({"error": f"Assessment failed: {str(exc)}"}), 500
        flash(f"Assessment error: {str(exc)}", "danger")
        return redirect(url_for("owasp.index"))
