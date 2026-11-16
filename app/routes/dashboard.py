from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required, current_user
from app.models import db, Target, Scan, Vulnerability, Report
from app.models.vulnerability import AIAnalysis
from app.ai.ai_config import AIConfig

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")


@dashboard_bp.route("", methods=["GET"])
@dashboard_bp.route("/", methods=["GET"])
@login_required
def index():
    """Security operations dashboard rendering live real-time database metrics."""
    # Build scoped queries based on RBAC
    target_query = Target.query.filter_by(is_active=True)
    scan_query = Scan.query

    if not current_user.is_admin():
        target_query = target_query.filter_by(owner_id=current_user.id)
        scan_query = scan_query.filter_by(user_id=current_user.id)

    total_targets = target_query.count()
    verified_targets = target_query.filter_by(is_verified=True).count()
    pending_targets = target_query.filter_by(is_verified=False).count()
    active_targets = total_targets

    total_scans = scan_query.count()
    completed_scans = scan_query.filter_by(status="completed").count()
    recent_targets = target_query.order_by(Target.created_at.desc()).limit(5).all()
    recent_scans = scan_query.order_by(Scan.created_at.desc()).limit(5).all()

    # Vulnerabilities, reports, and AI queries based on RBAC
    if current_user.is_admin():
        vuln_query = Vulnerability.query
        report_query = Report.query
        ai_query = AIAnalysis.query
    else:
        vuln_query = Vulnerability.query.join(Scan).filter(Scan.user_id == current_user.id)
        report_query = Report.query.filter_by(user_id=current_user.id)
        ai_query = AIAnalysis.query.filter_by(user_id=current_user.id)

    all_vulns = vuln_query.all()
    total_vulnerabilities = len(all_vulns)
    critical_vulns = sum(1 for v in all_vulns if (v.severity or "").upper() == "CRITICAL")
    high_vulns = sum(1 for v in all_vulns if (v.severity or "").upper() == "HIGH")
    medium_vulns = sum(1 for v in all_vulns if (v.severity or "").upper() == "MEDIUM")
    low_vulns = sum(1 for v in all_vulns if (v.severity or "").upper() == "LOW")
    info_vulns = sum(1 for v in all_vulns if (v.severity or "").upper() in ("INFORMATIONAL", "INFO"))

    # OWASP distribution
    owasp_counts = {}
    for v in all_vulns:
        cat = v.owasp_category or "A00:2025-Unknown"
        owasp_counts[cat] = owasp_counts.get(cat, 0) + 1

    # Report counts
    total_reports = report_query.count()
    complete_reports = report_query.filter_by(report_type="COMPLETE").count()
    vuln_reports = report_query.filter_by(report_type="VULN_DETAIL").count()
    exec_reports = report_query.filter_by(report_type="EXECUTIVE").count()
    recent_reports = report_query.order_by(Report.created_at.desc()).limit(5).all()

    # AI status
    ai_status = {
        "is_enabled": AIConfig.is_enabled(),
        "provider": AIConfig.get_provider() if AIConfig.is_enabled() else "Offline Deterministic Fallback",
        "model": AIConfig.get_model(),
        "total_analyses": ai_query.count(),
    }

    metrics = {
        "targets": {
            "total": total_targets,
            "verified": verified_targets,
            "pending": pending_targets,
            "active": active_targets,
        },
        "scans": {
            "total": total_scans,
            "completed": completed_scans,
        },
        "vulnerabilities": {
            "total": total_vulnerabilities,
            "critical": critical_vulns,
            "high": high_vulns,
            "medium": medium_vulns,
            "low": low_vulns,
            "info": info_vulns,
        },
        "owasp": {
            "total": len(owasp_counts),
            "distribution": owasp_counts,
        },
        "reports": {
            "total": total_reports,
            "complete": complete_reports,
            "vuln_detail": vuln_reports,
            "executive": exec_reports,
        },
        "ai_analyst": ai_status,
    }

    if request.is_json:
        return jsonify({
            "status": "success",
            "metrics": metrics,
            "recent_targets": [t.to_dict() for t in recent_targets],
            "recent_scans": [s.to_dict() for s in recent_scans],
            "recent_reports": [r.to_dict() for r in recent_reports],
        }), 200

    return render_template(
        "dashboard.html",
        metrics=metrics,
        recent_targets=recent_targets,
        recent_scans=recent_scans,
        recent_reports=recent_reports,
    )


@dashboard_bp.route("/status", methods=["GET"])
def dashboard_status():
    return jsonify({
        "module": "Security Dashboard",
        "version_target": "V3-V4",
        "status": "operational",
    })
