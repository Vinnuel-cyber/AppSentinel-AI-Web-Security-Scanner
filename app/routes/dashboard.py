from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required, current_user
from app.models import db, Target, Scan, Vulnerability

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")


@dashboard_bp.route("", methods=["GET"])
@dashboard_bp.route("/", methods=["GET"])
@login_required
def index():
    """Security dashboard rendering live real-time database metrics."""
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
    recent_targets = target_query.order_by(Target.created_at.desc()).limit(5).all()
    recent_scans = scan_query.order_by(Scan.created_at.desc()).limit(5).all()

    # Vulnerability counts (from user's scans)
    vuln_query = Vulnerability.query.join(Scan).filter(Scan.user_id == current_user.id if not current_user.is_admin() else True)
    total_vulnerabilities = vuln_query.count()
    critical_vulns = vuln_query.filter(Vulnerability.severity == "Critical").count()
    high_vulns = vuln_query.filter(Vulnerability.severity == "High").count()
    medium_vulns = vuln_query.filter(Vulnerability.severity == "Medium").count()
    low_vulns = vuln_query.filter(Vulnerability.severity == "Low").count()

    metrics = {
        "targets": {
            "total": total_targets,
            "verified": verified_targets,
            "pending": pending_targets,
            "active": active_targets,
        },
        "scans": {
            "total": total_scans,
        },
        "vulnerabilities": {
            "total": total_vulnerabilities,
            "critical": critical_vulns,
            "high": high_vulns,
            "medium": medium_vulns,
            "low": low_vulns,
        },
    }

    if request.is_json:
        return jsonify({
            "status": "success",
            "metrics": metrics,
            "recent_targets": [t.to_dict() for t in recent_targets],
            "recent_scans": [s.to_dict() for s in recent_scans],
        }), 200

    return render_template(
        "dashboard.html",
        metrics=metrics,
        recent_targets=recent_targets,
        recent_scans=recent_scans,
    )


@dashboard_bp.route("/status", methods=["GET"])
def dashboard_status():
    return jsonify({
        "module": "Security Dashboard",
        "version_target": "V3-V4",
        "status": "operational",
    })
