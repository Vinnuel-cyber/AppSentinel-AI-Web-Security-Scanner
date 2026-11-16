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
    Scan,
    ScanURL,
    Vulnerability,
    VulnerabilityEvidence,
)
from app.services.vulnerability_manager import VulnerabilityManager, VulnerabilityScanError

scanner_bp = Blueprint("scanner", __name__, url_prefix="/scanner")


@scanner_bp.route("", methods=["GET"])
@login_required
def index():
    """Vulnerability Scanner Dashboard & Filterable Findings Hub."""
    # Filter targets based on RBAC
    if current_user.role == "ADMIN":
        targets = Target.query.filter_by(is_active=True).order_by(Target.name.asc()).all()
        scans_query = Scan.query
        vulns_query = Vulnerability.query
    else:
        targets = Target.query.filter_by(owner_id=current_user.id, is_active=True).order_by(Target.name.asc()).all()
        scans_query = Scan.query.filter_by(user_id=current_user.id)
        vulns_query = Vulnerability.query.join(Scan).filter(Scan.user_id == current_user.id)

    verified_targets = [t for t in targets if t.is_verified and t.verification_status == "VERIFIED"]
    recent_scans = scans_query.order_by(Scan.created_at.desc()).limit(15).all()

    # Query params for filters
    severity_filter = request.args.get("severity", "").strip().upper()
    category_filter = request.args.get("category", "").strip()
    confidence_filter = request.args.get("confidence", "").strip().upper()
    target_filter = request.args.get("target_id", type=int)

    filtered_vulns = vulns_query
    if severity_filter:
        filtered_vulns = filtered_vulns.filter(Vulnerability.severity == severity_filter)
    if category_filter:
        filtered_vulns = filtered_vulns.filter(Vulnerability.vulnerability_type.ilike(f"%{category_filter}%"))
    if confidence_filter:
        filtered_vulns = filtered_vulns.filter(Vulnerability.confidence == confidence_filter)
    if target_filter:
        filtered_vulns = filtered_vulns.filter(Vulnerability.target_id == target_filter)

    vulnerabilities = filtered_vulns.order_by(Vulnerability.created_at.desc()).limit(50).all()

    # Compute global vulnerability metrics
    all_vulns = vulns_query.all()
    metrics = {
        "total": len(all_vulns),
        "critical": sum(1 for v in all_vulns if v.severity.upper() == "CRITICAL"),
        "high": sum(1 for v in all_vulns if v.severity.upper() == "HIGH"),
        "medium": sum(1 for v in all_vulns if v.severity.upper() == "MEDIUM"),
        "low": sum(1 for v in all_vulns if v.severity.upper() == "LOW"),
        "info": sum(1 for v in all_vulns if v.severity.upper() in ("INFORMATIONAL", "INFO")),
    }

    return render_template(
        "scanner/index.html",
        targets=targets,
        verified_targets=verified_targets,
        recent_scans=recent_scans,
        vulnerabilities=vulnerabilities,
        metrics=metrics,
        selected_severity=severity_filter,
        selected_category=category_filter,
        selected_confidence=confidence_filter,
        selected_target_id=target_filter,
    )


@scanner_bp.route("/vulnerabilities", methods=["GET"])
@login_required
def vulnerabilities_list():
    """Direct route for filterable vulnerability findings hub."""
    return index()


@scanner_bp.route("/start/<int:target_id>", methods=["POST"])
@login_required
def start_scan(target_id: int):
    """Launch an evidence-based vulnerability scan against an authorized target."""
    target = db.session.get(Target, target_id)
    if not target or not target.is_active:
        if request.is_json:
            return jsonify({"error": "Target not found or deactivated."}), 404
        flash("Target not found or deactivated.", "danger")
        return redirect(url_for("scanner.index"))

    allow_private = current_app.config.get("TESTING", False)

    # Validate authorization
    try:
        VulnerabilityManager.validate_target_for_scan(target, current_user, allow_private=allow_private)
    except VulnerabilityScanError as err:
        if request.is_json:
            return jsonify({"error": str(err)}), 403
        flash(str(err), "danger")
        return redirect(url_for("scanner.index"))

    # Check for duplicate concurrent scan on this target
    active_scan = Scan.query.filter_by(target_id=target.id, status="running").first()
    if active_scan:
        if request.is_json:
            return jsonify({
                "error": f"A scan (#{active_scan.id}) is already currently running for target '{target.name}'.",
                "active_scan_id": active_scan.id,
            }), 409
        flash(f"A scan is already active for {target.name}. Please wait for it to complete.", "warning")
        return redirect(url_for("scanner.results", scan_id=active_scan.id))

    # Initialize new scan
    scan = Scan(
        target_id=target.id,
        user_id=current_user.id,
        scan_type="full",
        status="pending",
    )
    db.session.add(scan)
    db.session.commit()

    # Run scan
    try:
        VulnerabilityManager.run_vulnerability_scan(
            scan_id=scan.id,
            allow_private=allow_private,
            timeout=current_app.config.get("SCAN_TIMEOUT", 6.0),
        )
        if request.is_json:
            return jsonify({
                "message": "Vulnerability scan completed successfully.",
                "scan_id": scan.id,
                "status": scan.status,
                "total_vulnerabilities": scan.total_vulnerabilities,
                "risk_score": scan.risk_score,
                "overall_risk": scan.overall_risk,
            }), 201
        flash(f"Vulnerability scan #{scan.id} completed. Found {scan.total_vulnerabilities} findings.", "success")
        return redirect(url_for("scanner.results", scan_id=scan.id))
    except Exception as exc:
        current_app.logger.error("Scan execution failed: %s", exc)
        if request.is_json:
            return jsonify({"error": f"Scan execution failed: {str(exc)}", "scan_id": scan.id}), 500
        flash(f"Scan encountered an error: {str(exc)}", "danger")
        return redirect(url_for("scanner.results", scan_id=scan.id))


@scanner_bp.route("/results/<int:scan_id>", methods=["GET"])
@login_required
def results(scan_id: int):
    """View detailed vulnerability scan report and findings."""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        abort(404)

    target = db.session.get(Target, scan.target_id)
    if not target:
        abort(404)

    # Cross-user authorization check
    if current_user.role != "ADMIN" and scan.user_id != current_user.id:
        abort(403)

    vulnerabilities = scan.vulnerabilities.order_by(
        db.case(
            {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFORMATIONAL": 5},
            value=Vulnerability.severity,
            else_=6,
        ).asc(),
        Vulnerability.created_at.desc(),
    ).all()

    return render_template(
        "scanner/results.html",
        scan=scan,
        target=target,
        vulnerabilities=vulnerabilities,
    )


@scanner_bp.route("/vulnerability/<int:vuln_id>", methods=["GET"])
@login_required
def vulnerability_details(vuln_id: int):
    """Detailed view for a single confirmed vulnerability finding."""
    vuln = db.session.get(Vulnerability, vuln_id)
    if not vuln:
        abort(404)

    scan = db.session.get(Scan, vuln.scan_id)
    target = db.session.get(Target, vuln.target_id or scan.target_id)

    # Cross-user check
    if current_user.role != "ADMIN" and scan.user_id != current_user.id:
        abort(403)

    evidences = vuln.evidences.all()

    return render_template(
        "scanner/vulnerability_details.html",
        vuln=vuln,
        scan=scan,
        target=target,
        evidences=evidences,
    )


@scanner_bp.route("/cancel/<int:scan_id>", methods=["POST"])
@login_required
def cancel_scan(scan_id: int):
    """Cancel an active or pending vulnerability scan."""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        abort(404)

    if current_user.role != "ADMIN" and scan.user_id != current_user.id:
        abort(403)

    if scan.status in ("completed", "failed", "cancelled"):
        if request.is_json:
            return jsonify({"message": f"Scan is already {scan.status}."}), 400
        flash(f"Scan is already {scan.status}.", "info")
        return redirect(url_for("scanner.results", scan_id=scan.id))

    scan.status = "cancelled"
    scan.completed_at = datetime.now(timezone.utc)
    db.session.commit()

    if request.is_json:
        return jsonify({"message": "Vulnerability scan cancelled successfully.", "scan_id": scan.id}), 200
    flash("Vulnerability scan was cancelled.", "info")
    return redirect(url_for("scanner.results", scan_id=scan.id))


@scanner_bp.route("/api/findings/<int:scan_id>", methods=["GET"])
@login_required
def api_findings(scan_id: int):
    """REST API: Get all structured findings for a scan."""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found."}), 404

    if current_user.role != "ADMIN" and scan.user_id != current_user.id:
        return jsonify({"error": "Forbidden."}), 403

    vulns = scan.vulnerabilities.all()
    return jsonify({
        "scan": scan.to_dict(),
        "total_findings": len(vulns),
        "vulnerabilities": [v.to_dict() for v in vulns],
    }), 200


@scanner_bp.route("/status", methods=["GET"])
def scanner_status():
    """Module health check and status."""
    return jsonify({
        "module": "Vulnerability Scanner Engine",
        "version": "V6.0",
        "status": "active",
        "capabilities": [
            "SQL Injection (Safe Error-Based / Differential Syntax)",
            "Reflected XSS (Benign Marker DOM Analysis)",
            "Insecure Cookie Security Attributes",
            "Security Misconfiguration & Header Hardening",
            "Technical Information Disclosure & Stack Traces",
            "Directory Listing & Index Exposure",
            "Sensitive Data Pattern Detection with Auto-Redaction",
        ],
    })
