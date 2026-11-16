"""AppSentinel Report Management Controller (V9).

Routes for:
- Report Center SOC Dashboard view.
- Asynchronous and synchronous PDF report generation.
- Historical report auditing.
- Secure, path-traversal-protected report downloads.
- Authorized report deletion.
"""

from flask import (
    Blueprint,
    render_template,
    request,
    jsonify,
    abort,
    send_file,
    current_app,
)
from flask_login import login_required, current_user

from app.models import db, Target, Scan, Report
from app.reports.report_service import ReportService
from app.ai.context_builder import ContextBuilder

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


@reports_bp.route("", methods=["GET"])
@reports_bp.route("/", methods=["GET"])
@login_required
def index():
    """Report Center dashboard view."""
    is_admin = current_user.role == "ADMIN"

    if is_admin:
        targets = Target.query.filter_by(is_active=True).all()
        scans = Scan.query.order_by(Scan.created_at.desc()).limit(30).all()
        recent_reports = Report.query.order_by(Report.created_at.desc()).limit(20).all()
    else:
        targets = Target.query.filter_by(owner_id=current_user.id, is_active=True).all()
        target_ids = [t.id for t in targets]
        scans = (
            Scan.query.filter(Scan.target_id.in_(target_ids))
            .order_by(Scan.created_at.desc())
            .limit(30)
            .all()
            if target_ids
            else []
        )
        recent_reports = (
            Report.query.filter_by(user_id=current_user.id)
            .order_by(Report.created_at.desc())
            .limit(20)
            .all()
        )

    return render_template(
        "reports/index.html",
        targets=targets,
        scans=scans,
        reports=recent_reports,
    )


@reports_bp.route("/history", methods=["GET"])
@login_required
def history():
    """Return JSON history of authorized reports."""
    is_admin = current_user.role == "ADMIN"
    reports_data = ReportService.get_user_reports(current_user.id, is_admin=is_admin)
    return jsonify({"success": True, "reports": reports_data})


@reports_bp.route("/<int:report_id>", methods=["GET"])
@login_required
def get_report(report_id: int):
    """Retrieve metadata for a specific report."""
    is_admin = current_user.role == "ADMIN"
    report = ReportService.get_report_by_id(report_id, current_user.id, is_admin=is_admin)
    if not report:
        return jsonify({"error": "Not Found", "message": "Report not found or unauthorized access."}), 404

    return jsonify({"success": True, "report": report.to_dict()})


@reports_bp.route("/generate", methods=["POST"])
@login_required
def generate():
    """Generate a new PDF security assessment report."""
    data = request.get_json(silent=True) or request.form or {}

    scan_id = data.get("scan_id")
    if not scan_id:
        return jsonify({"error": "Bad Request", "message": "scan_id parameter is required."}), 400

    try:
        scan_id = int(scan_id)
    except (ValueError, TypeError):
        return jsonify({"error": "Bad Request", "message": "Invalid scan_id format."}), 400

    target_id = data.get("target_id")
    if target_id:
        try:
            target_id = int(target_id)
        except (ValueError, TypeError):
            target_id = None

    report_type = data.get("report_type", "COMPLETE").upper().strip()
    is_admin = current_user.role == "ADMIN"

    success, report, msg = ReportService.generate_report(
        user_id=current_user.id,
        scan_id=scan_id,
        target_id=target_id,
        report_type=report_type,
        is_admin=is_admin,
    )

    if not success:
        return jsonify({"error": "Report generation failed", "message": msg}), 400

    return jsonify({
        "success": True,
        "message": msg,
        "report": report.to_dict() if report else None,
        "download_url": f"/reports/download/{report.id}" if report else None,
    }), 201


@reports_bp.route("/download/<int:report_id>", methods=["GET"])
@login_required
def download_report(report_id: int):
    """Securely download a generated PDF report with ownership validation and path traversal checks."""
    is_admin = current_user.role == "ADMIN"
    success, file_path, filename, err_msg = ReportService.get_report_file_for_download(
        report_id=report_id,
        user_id=current_user.id,
        is_admin=is_admin,
    )

    if not success:
        if "integrity" in err_msg.lower():
            return jsonify({"error": "Integrity Verification Failed", "message": err_msg}), 400
        return jsonify({"error": "Unauthorized / Not Found", "message": err_msg}), 404

    return send_file(
        file_path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )


@reports_bp.route("/<int:report_id>", methods=["DELETE"])
@login_required
def delete_report(report_id: int):
    """Delete a report record and its associated physical file."""
    is_admin = current_user.role == "ADMIN"
    success, msg = ReportService.delete_report(report_id, current_user.id, is_admin=is_admin)

    if not success:
        return jsonify({"error": "Delete failed", "message": msg}), 404

    return jsonify({"success": True, "message": msg})


@reports_bp.route("/status", methods=["GET"])
def reports_status():
    """Module health endpoint."""
    return jsonify({
        "module": "Report Generator",
        "version": "V9",
        "engine": "ReportLab 5.1+",
        "supported_types": ["COMPLETE", "VULN_DETAIL", "EXECUTIVE"],
        "status": "operational",
    })
