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
    Scan,
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
    """OWASP Top 10 Security Assessment Dashboard with 2025/2021 framework filtering."""
    version_filter = request.args.get("version", "2025").strip()
    if version_filter not in ("2025", "2021", "all"):
        version_filter = "2025"

    if current_user.role == "ADMIN":
        targets = Target.query.filter_by(is_active=True).order_by(Target.name.asc()).all()
        assessments_query = OWASPAssessment.query
        mappings_query = OWASPFindingMapping.query
    else:
        targets = Target.query.filter_by(owner_id=current_user.id, is_active=True).order_by(Target.name.asc()).all()
        assessments_query = OWASPAssessment.query.filter_by(user_id=current_user.id)
        user_target_ids = [t.id for t in targets]
        mappings_query = (
            OWASPFindingMapping.query.join(Vulnerability, OWASPFindingMapping.vulnerability_id == Vulnerability.id)
            .outerjoin(Scan, Vulnerability.scan_id == Scan.id)
            .filter(
                (Vulnerability.target_id.in_(user_target_ids))
                | (Scan.user_id == current_user.id)
                | (OWASPFindingMapping.assessment_id.in_(
                    db.session.query(OWASPAssessment.id).filter(OWASPAssessment.user_id == current_user.id)
                ))
            )
            if user_target_ids
            else OWASPFindingMapping.query.filter(
                OWASPFindingMapping.assessment_id.in_(
                    db.session.query(OWASPAssessment.id).filter(OWASPAssessment.user_id == current_user.id)
                )
            )
        )

    # Filter assessments by framework version if specified
    if version_filter in ("2025", "2021"):
        assessments = assessments_query.filter_by(framework_version=version_filter).order_by(OWASPAssessment.created_at.desc()).limit(20).all()
        mappings_filtered = mappings_query.filter(OWASPFindingMapping.framework_version == version_filter).all()
        category_definitions = OWASPMapper.get_categories(version_filter)
    else:
        assessments = assessments_query.order_by(OWASPAssessment.created_at.desc()).limit(20).all()
        mappings_filtered = mappings_query.all()
        category_definitions = OWASPMapper.get_categories("2025")

    verified_targets = [t for t in targets if t.is_verified and t.verification_status == "VERIFIED"]

    # Compute category distribution for active category definitions
    category_counts = {cat_code: 0 for cat_code in category_definitions.keys()}
    for m in mappings_filtered:
        if m.primary_category_code in category_counts:
            category_counts[m.primary_category_code] += 1

    confidence_counts = {
        "HIGH": sum(1 for m in mappings_filtered if m.confidence == "HIGH"),
        "MEDIUM": sum(1 for m in mappings_filtered if m.confidence == "MEDIUM"),
        "LOW": sum(1 for m in mappings_filtered if m.confidence == "LOW"),
    }

    return render_template(
        "owasp/dashboard.html",
        targets=targets,
        verified_targets=verified_targets,
        assessments=assessments,
        total_mappings=len(mappings_filtered),
        category_counts=category_counts,
        category_definitions=category_definitions,
        confidence_counts=confidence_counts,
        framework_version=version_filter if version_filter in ("2025", "2021") else "2025",
        active_version=version_filter,
    )


@owasp_bp.route("/assessment/<int:target_id>", methods=["GET"])
@login_required
def target_assessment(target_id: int):
    """View detailed OWASP Top 10 assessment for an authorized target (preserving exact version)."""
    target = db.session.get(Target, target_id)
    if not target or not target.is_active:
        abort(404)

    # RBAC / Ownership enforcement
    if current_user.role != "ADMIN" and target.owner_id != current_user.id:
        abort(403)

    version_param = request.args.get("version")
    if version_param in ("2025", "2021"):
        latest_assessment = (
            OWASPAssessment.query.filter_by(target_id=target.id, framework_version=version_param)
            .order_by(OWASPAssessment.created_at.desc())
            .first()
        )
    else:
        latest_assessment = (
            OWASPAssessment.query.filter_by(target_id=target.id)
            .order_by(OWASPAssessment.created_at.desc())
            .first()
        )

    # Determine framework version from assessment or fallback to 2025
    assessment_version = latest_assessment.framework_version if latest_assessment else "2025"
    category_definitions = OWASPMapper.get_categories(assessment_version)

    # Fetch mappings: if assessment exists, fetch linked mappings; otherwise fetch target mappings
    if latest_assessment and latest_assessment.mappings.count() > 0:
        mappings = latest_assessment.mappings.order_by(OWASPFindingMapping.primary_category_code.asc()).all()
    else:
        mappings = (
            OWASPFindingMapping.query.join(Vulnerability)
            .filter(Vulnerability.target_id == target.id, OWASPFindingMapping.framework_version == assessment_version)
            .order_by(OWASPFindingMapping.primary_category_code.asc())
            .all()
        )

    return render_template(
        "owasp/assessment.html",
        target=target,
        assessment=latest_assessment,
        mappings=mappings,
        category_definitions=category_definitions,
        framework_version=assessment_version,
    )


@owasp_bp.route("/analyze/<int:target_id>", methods=["POST"])
@login_required
def analyze_target(target_id: int):
    """Trigger an OWASP Top 10 and Risk Assessment for a verified target (defaulting to 2025)."""
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

    # Determine framework version requested
    req_json = request.get_json(silent=True) or {}
    req_version = req_json.get("version") or request.form.get("version") or request.args.get("version") or "2025"
    if req_version not in ("2025", "2021"):
        req_version = "2025"

    try:
        assessment = OWASPService.run_target_assessment(target.id, current_user.id, framework_version=req_version)
        if request.is_json:
            return jsonify({
                "message": f"OWASP Top 10:{assessment.framework_version} assessment completed successfully.",
                "assessment_id": assessment.id,
                "framework_version": assessment.framework_version,
                "total_findings_mapped": assessment.total_findings_mapped,
                "top_category": assessment.top_category,
                "summary": assessment.get_summary(),
            }), 201
        flash(f"OWASP Top 10:{assessment.framework_version} Assessment completed ({assessment.total_findings_mapped} findings mapped).", "success")
        return redirect(url_for("owasp.target_assessment", target_id=target.id, version=assessment.framework_version))
    except Exception as exc:
        current_app.logger.error("OWASP assessment failed: %s", exc)
        if request.is_json:
            return jsonify({"error": f"Assessment failed: {str(exc)}"}), 500
        flash(f"Assessment error: {str(exc)}", "danger")
        return redirect(url_for("owasp.index"))
