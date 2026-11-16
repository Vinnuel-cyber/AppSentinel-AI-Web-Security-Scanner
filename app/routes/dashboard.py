from datetime import datetime, timezone
from flask import Blueprint, render_template, jsonify, request, url_for
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
    running_scans = scan_query.filter_by(status="running").count()
    failed_scans = scan_query.filter(Scan.status.in_(["failed", "cancelled"])).count()
    recent_targets = target_query.order_by(Target.created_at.desc()).limit(5).all()
    recent_scans = scan_query.order_by(Scan.created_at.desc()).limit(8).all()

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

    # AI status & latest diagnosis with explicit enterprise posture labels
    has_api_key = bool(AIConfig.get_api_key())
    ai_is_live = AIConfig.is_enabled() and has_api_key
    latest_analysis = ai_query.order_by(AIAnalysis.created_at.desc()).first()

    if ai_is_live:
        ai_mode_label = "LIVE AI ANALYSIS"
        ai_mode_badge = "badge-live-ai"
    elif AIConfig.is_enabled():
        ai_mode_label = "OFFLINE RULE-BASED ANALYSIS"
        ai_mode_badge = "badge-offline-ai"
    else:
        ai_mode_label = "AI PROVIDER NOT CONFIGURED"
        ai_mode_badge = "badge-disabled-ai"

    ai_status = {
        "is_enabled": AIConfig.is_enabled(),
        "has_api_key": has_api_key,
        "is_live": ai_is_live,
        "mode_label": ai_mode_label,
        "mode_badge": ai_mode_badge,
        "display_status": "Live Cloud AI Active" if ai_is_live else "Offline Security Analysis Active",
        "provider": AIConfig.get_provider() if ai_is_live else "Deterministic Rule-Based Engine",
        "model": AIConfig.get_model() if ai_is_live else "Deterministic Fallback",
        "total_analyses": ai_query.count(),
    }

    # Honest Security Posture Assessment (Ground-truth DB values only, no fabricated scores)
    if total_scans == 0:
        posture_status = "No Assessment Data"
        posture_class = "secondary"
        posture_desc = "Enroll targets and run security scans to initiate posture assessment."
    elif critical_vulns > 0:
        posture_status = "Critical Findings Detected"
        posture_class = "danger"
        posture_desc = f"{critical_vulns} critical vulnerabilities require immediate remediation triage."
    elif high_vulns > 0 or total_vulnerabilities > 0:
        posture_status = "Findings Require Review"
        posture_class = "warning"
        posture_desc = f"{total_vulnerabilities} findings detected across active attack surface."
    else:
        posture_status = "Assessment Available"
        posture_class = "success"
        posture_desc = "Scans completed with 0 critical/high findings identified."

    # Identify most affected target among user's authorized scope
    most_affected_target = None
    target_vuln_map = {}
    for v in all_vulns:
        if v.target_id:
            target_vuln_map[v.target_id] = target_vuln_map.get(v.target_id, 0) + 1
    if target_vuln_map:
        top_tid = max(target_vuln_map, key=target_vuln_map.get)
        top_tgt = db.session.get(Target, top_tid)
        if top_tgt:
            most_affected_target = {
                "id": top_tgt.id,
                "name": top_tgt.name,
                "domain": top_tgt.domain,
                "count": target_vuln_map[top_tid],
            }

    # Highest priority remediation item from actual findings
    top_remediation = None
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0, "INFO": 0}
    sorted_vulns = sorted(
        all_vulns,
        key=lambda v: (severity_order.get((v.severity or "").upper(), 0), v.cvss_score or 0.0),
        reverse=True,
    )
    if sorted_vulns:
        top_v = sorted_vulns[0]
        top_remediation = {
            "id": top_v.id,
            "title": top_v.title,
            "severity": (top_v.severity or "INFO").upper(),
            "cvss_score": top_v.cvss_score,
            "owasp_category": top_v.owasp_category,
            "affected_url": top_v.affected_url,
            "remediation": top_v.remediation or "Review endpoint security configuration and input handling.",
        }

    now_utc = datetime.now(timezone.utc)

    # Historical scan activity for Chart.js timeline
    scan_timeline = scan_query.order_by(Scan.created_at.desc()).limit(8).all()
    scan_timeline.reverse()
    scan_activity = {
        "labels": [f"#{s.id} ({s.created_at.strftime('%m/%d') if s.created_at else ''})" for s in scan_timeline],
        "findings": [s.total_vulnerabilities for s in scan_timeline],
        "critical": [s.critical_count for s in scan_timeline],
        "risk_scores": [round(s.risk_score or 0.0, 1) for s in scan_timeline],
    }

    # Real database chronological security activity feed
    raw_events = []
    for t in recent_targets:
        raw_events.append({
            "category": "target",
            "icon": "fa-crosshairs",
            "color": "text-info",
            "badge_class": "badge-role-user",
            "title": f"Target Enrolled: {t.name}",
            "detail": f"{t.domain} • {t.environment}",
            "time": t.created_at,
            "url": url_for("targets.details", target_id=t.id),
        })
        if t.is_verified and t.verified_at:
            raw_events.append({
                "category": "verification",
                "icon": "fa-circle-check",
                "color": "text-success",
                "badge_class": "bg-success-subtle text-success",
                "title": f"Target Verified: {t.domain}",
                "detail": f"Verified via {t.verification_method or 'DNS/HTTP'}",
                "time": t.verified_at,
                "url": url_for("targets.details", target_id=t.id),
            })

    for s in recent_scans:
        target_label = s.target.name if s.target else f"Target #{s.target_id}"
        raw_events.append({
            "category": "scan",
            "icon": "fa-shield-virus",
            "color": "text-success" if s.status == "completed" else "text-warning",
            "badge_class": "bg-success-subtle text-success" if s.status == "completed" else "bg-warning-subtle text-warning",
            "title": f"Scan #{s.id} ({s.status.capitalize()})",
            "detail": f"{target_label} • {s.total_vulnerabilities} findings",
            "time": s.completed_at or s.created_at,
            "url": url_for("scanner.results", scan_id=s.id),
        })

    for r in recent_reports:
        raw_events.append({
            "category": "report",
            "icon": "fa-file-pdf",
            "color": "text-danger",
            "badge_class": "bg-danger-subtle text-danger",
            "title": f"PDF Compiled: {r.report_type}",
            "detail": f"{r.title} • SHA-256 verified",
            "time": r.created_at,
            "url": url_for("reports.download_report", report_id=r.id),
        })

    recent_ai = ai_query.order_by(AIAnalysis.created_at.desc()).limit(3).all()
    for a in recent_ai:
        raw_events.append({
            "category": "ai",
            "icon": "fa-brain",
            "color": "text-info",
            "badge_class": "bg-info-subtle text-info",
            "title": "AI Finding Diagnosis",
            "detail": f"Finding #{a.vulnerability_id} • {'Offline Fallback' if a.is_fallback else 'OpenAI'}",
            "time": a.created_at,
            "url": url_for("ai.index"),
        })

    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    def event_time(e):
        t = e.get("time")
        if t is None:
            return epoch
        if t.tzinfo is None:
            return t.replace(tzinfo=timezone.utc)
        return t

    raw_events.sort(key=event_time, reverse=True)
    activity_feed = raw_events[:8]

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
            "running": running_scans,
            "failed": failed_scans,
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
        "posture": {
            "status": posture_status,
            "status_class": posture_class,
            "description": posture_desc,
            "critical": critical_vulns,
            "high": high_vulns,
            "medium": medium_vulns,
            "low": low_vulns,
            "info": info_vulns,
            "most_affected_target": most_affected_target,
            "top_remediation": top_remediation,
        },
        "meta": {
            "current_date": now_utc.strftime("%A, %B %d, %Y"),
            "last_refresh": now_utc.strftime("%d %b %Y, %H:%M UTC"),
        },
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
        latest_analysis=latest_analysis,
        activity_feed=activity_feed,
        scan_activity=scan_activity,
    )


@dashboard_bp.route("/status", methods=["GET"])
def dashboard_status():
    return jsonify({
        "module": "Security Dashboard",
        "version_target": "V3-V4",
        "status": "operational",
    })
