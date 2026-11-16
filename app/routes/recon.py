from datetime import datetime, timezone
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
    ReconScan,
    DiscoveredEndpoint,
    TechnologyFingerprint,
    DNSRecord,
    SecurityHeaderFinding,
    WebsiteMetadata,
)
from app.services.recon_manager import ReconManager, ReconAuthorizationError

recon_bp = Blueprint("recon", __name__, url_prefix="/recon")


@recon_bp.route("", methods=["GET"])
@login_required
def index():
    """Recon Hub - Targets overview and recent scans."""
    if current_user.role == "ADMIN":
        targets = Target.query.filter_by(is_active=True).order_by(Target.name.asc()).all()
        recent_scans = ReconScan.query.order_by(ReconScan.created_at.desc()).limit(20).all()
    else:
        targets = Target.query.filter_by(owner_id=current_user.id, is_active=True).order_by(Target.name.asc()).all()
        recent_scans = ReconScan.query.filter_by(user_id=current_user.id).order_by(ReconScan.created_at.desc()).limit(20).all()

    verified_targets = [t for t in targets if t.is_verified and t.verification_status == "VERIFIED"]
    unverified_targets = [t for t in targets if not t.is_verified or t.verification_status != "VERIFIED"]

    return render_template(
        "recon/index.html",
        targets=targets,
        verified_targets=verified_targets,
        unverified_targets=unverified_targets,
        recent_scans=recent_scans,
    )


@recon_bp.route("/start/<int:target_id>", methods=["POST"])
@login_required
def start_scan(target_id: int):
    """Initiate a reconnaissance scan against an authorized, verified target."""
    target = db.session.get(Target, target_id)
    if not target or not target.is_active:
        if request.is_json:
            return jsonify({"error": "Target not found or inactive."}), 404
        flash("Target not found or inactive.", "danger")
        return redirect(url_for("recon.index"))

    # Validate authorization & verification
    allow_private = current_app.config.get("TESTING", False)
    try:
        ReconManager.validate_target_for_recon(target, current_user, allow_private=allow_private)
    except ReconAuthorizationError as auth_err:
        if request.is_json:
            return jsonify({"error": str(auth_err)}), 403
        flash(str(auth_err), "danger")
        return redirect(url_for("targets.details", target_id=target.id))

    # Create pending ReconScan
    scan = ReconScan(
        target_id=target.id,
        user_id=current_user.id,
        status="pending",
    )
    db.session.add(scan)
    db.session.commit()

    # Execute synchronous scan (or asynchronous if worker configured)
    try:
        ReconManager.run_recon_scan(
            scan_id=scan.id,
            allow_private=allow_private,
            timeout=current_app.config.get("SCAN_TIMEOUT", 8.0),
        )
        if request.is_json:
            return jsonify({
                "message": "Reconnaissance scan completed successfully.",
                "scan_id": scan.id,
                "status": scan.status,
            }), 201
        flash(f"Reconnaissance scan #{scan.id} completed successfully.", "success")
        return redirect(url_for("recon.results", scan_id=scan.id))
    except Exception as exc:
        current_app.logger.error("Recon scan failed: %s", exc)
        if request.is_json:
            return jsonify({
                "error": f"Scan failed: {str(exc)}",
                "scan_id": scan.id,
                "status": "failed",
            }), 500
        flash(f"Scan encountered an error: {str(exc)}", "warning")
        return redirect(url_for("recon.results", scan_id=scan.id))


@recon_bp.route("/results/<int:scan_id>", methods=["GET"])
@login_required
def results(scan_id: int):
    """Display comprehensive reconnaissance findings for a specific scan."""
    scan = db.session.get(ReconScan, scan_id)
    if not scan:
        abort(404)

    target = db.session.get(Target, scan.target_id)
    if not target:
        abort(404)

    # Cross-user isolation check
    if current_user.role != "ADMIN" and scan.user_id != current_user.id:
        abort(403)

    endpoints = scan.endpoints.order_by(DiscoveredEndpoint.discovered_at.asc()).all()
    technologies = scan.technologies.order_by(TechnologyFingerprint.category.asc()).all()
    dns_records = scan.dns_records.order_by(DNSRecord.record_type.asc()).all()
    security_headers = scan.security_headers.order_by(SecurityHeaderFinding.status.asc()).all()
    metadata = scan.metadata_record

    return render_template(
        "recon/results.html",
        scan=scan,
        target=target,
        endpoints=endpoints,
        technologies=technologies,
        dns_records=dns_records,
        security_headers=security_headers,
        metadata=metadata,
    )


@recon_bp.route("/history/<int:target_id>", methods=["GET"])
@login_required
def history(target_id: int):
    """View historical recon scans for a given target."""
    target = db.session.get(Target, target_id)
    if not target or not target.is_active:
        abort(404)

    if current_user.role != "ADMIN" and target.owner_id != current_user.id:
        abort(403)

    scans = ReconScan.query.filter_by(target_id=target.id).order_by(ReconScan.created_at.desc()).all()

    return render_template(
        "recon/history.html",
        target=target,
        scans=scans,
    )


@recon_bp.route("/cancel/<int:scan_id>", methods=["POST"])
@login_required
def cancel_scan(scan_id: int):
    """Cancel a pending or active recon scan."""
    scan = db.session.get(ReconScan, scan_id)
    if not scan:
        abort(404)

    if current_user.role != "ADMIN" and scan.user_id != current_user.id:
        abort(403)

    if scan.status in ("completed", "failed", "cancelled"):
        if request.is_json:
            return jsonify({"message": f"Scan is already {scan.status}."}), 400
        flash(f"Scan is already {scan.status}.", "info")
        return redirect(url_for("recon.results", scan_id=scan.id))

    scan.status = "cancelled"
    scan.completed_at = datetime.now(timezone.utc)
    db.session.commit()

    if request.is_json:
        return jsonify({"message": "Scan cancelled successfully.", "scan_id": scan.id}), 200
    flash("Reconnaissance scan was cancelled.", "info")
    return redirect(url_for("recon.results", scan_id=scan.id))


@recon_bp.route("/findings/<int:scan_id>", methods=["GET"])
@login_required
def findings_json(scan_id: int):
    """REST API: Return full reconnaissance findings as JSON."""
    scan = db.session.get(ReconScan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found."}), 404

    if current_user.role != "ADMIN" and scan.user_id != current_user.id:
        return jsonify({"error": "Forbidden."}), 403

    target = db.session.get(Target, scan.target_id)

    return jsonify({
        "scan": scan.to_dict(),
        "target": {
            "id": target.id,
            "name": target.name,
            "domain": target.domain,
            "target_url": target.target_url,
            "environment": target.environment,
        } if target else None,
        "technologies": [t.to_dict() for t in scan.technologies.all()],
        "security_headers": [h.to_dict() for h in scan.security_headers.all()],
        "dns_records": [d.to_dict() for d in scan.dns_records.all()],
        "endpoints": [e.to_dict() for e in scan.endpoints.all()],
        "metadata": scan.metadata_record.to_dict() if scan.metadata_record else None,
    }), 200
