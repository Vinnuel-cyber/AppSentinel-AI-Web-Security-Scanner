from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    jsonify,
    abort,
)
from flask_login import login_required, current_user
from app.models import (
    db,
    Target,
    Vulnerability,
    RiskAssessment,
    FindingCorrelation,
    RemediationRecommendation,
)
from app.security import CVSS4RiskEngine, RiskPrioritizer

risk_bp = Blueprint("risk", __name__, url_prefix="/risk")


@risk_bp.route("", methods=["GET"])
@login_required
def index():
    """Enterprise Risk Engine Dashboard."""
    if current_user.role == "ADMIN":
        targets = Target.query.filter_by(is_active=True).all()
        risk_query = RiskAssessment.query
        corr_query = FindingCorrelation.query
        rem_query = RemediationRecommendation.query
    else:
        targets = Target.query.filter_by(owner_id=current_user.id, is_active=True).all()
        target_ids = [t.id for t in targets]
        risk_query = RiskAssessment.query.filter(RiskAssessment.target_id.in_(target_ids)) if target_ids else RiskAssessment.query.filter_by(target_id=-1)
        corr_query = FindingCorrelation.query.filter(FindingCorrelation.target_id.in_(target_ids)) if target_ids else FindingCorrelation.query.filter_by(target_id=-1)
        rem_query = RemediationRecommendation.query.filter(RemediationRecommendation.target_id.in_(target_ids)) if target_ids else RemediationRecommendation.query.filter_by(target_id=-1)

    all_risks = risk_query.all()
    correlations = corr_query.order_by(FindingCorrelation.created_at.desc()).limit(15).all()
    remediations = rem_query.order_by(RemediationRecommendation.created_at.desc()).limit(10).all()

    # Severity distribution
    severity_counts = {
        "Critical": sum(1 for r in all_risks if r.severity_rating == "Critical"),
        "High": sum(1 for r in all_risks if r.severity_rating == "High"),
        "Medium": sum(1 for r in all_risks if r.severity_rating == "Medium"),
        "Low": sum(1 for r in all_risks if r.severity_rating == "Low"),
        "None": sum(1 for r in all_risks if r.severity_rating == "None"),
    }

    # Operational Priority distribution (P1-P5)
    priority_counts = {
        "P1": sum(1 for r in all_risks if r.operational_priority == "P1"),
        "P2": sum(1 for r in all_risks if r.operational_priority == "P2"),
        "P3": sum(1 for r in all_risks if r.operational_priority == "P3"),
        "P4": sum(1 for r in all_risks if r.operational_priority == "P4"),
        "P5": sum(1 for r in all_risks if r.operational_priority == "P5"),
    }

    # Rank targets by highest CVSS score or critical count
    target_rankings = []
    for tgt in targets:
        tgt_risks = [r for r in all_risks if r.target_id == tgt.id]
        if tgt_risks:
            max_score = max(r.cvss_score for r in tgt_risks)
            p1_cnt = sum(1 for r in tgt_risks if r.operational_priority == "P1")
            target_rankings.append({
                "target": tgt,
                "max_score": max_score,
                "p1_count": p1_cnt,
                "total_risks": len(tgt_risks),
            })
    target_rankings.sort(key=lambda x: (x["max_score"], x["p1_count"]), reverse=True)

    return render_template(
        "risk/dashboard.html",
        targets=targets,
        target_rankings=target_rankings,
        severity_counts=severity_counts,
        priority_counts=priority_counts,
        correlations=correlations,
        remediations=remediations,
        total_assessed=len(all_risks),
    )


@risk_bp.route("/target/<int:target_id>", methods=["GET"])
@login_required
def target_risk(target_id: int):
    """View detailed risk posture and prioritized findings for a specific target."""
    target = db.session.get(Target, target_id)
    if not target or not target.is_active:
        abort(404)

    if current_user.role != "ADMIN" and target.owner_id != current_user.id:
        abort(403)

    risk_records = (
        RiskAssessment.query.filter_by(target_id=target.id)
        .order_by(RiskAssessment.cvss_score.desc())
        .all()
    )

    correlations = (
        FindingCorrelation.query.filter_by(target_id=target.id)
        .order_by(FindingCorrelation.created_at.desc())
        .all()
    )

    return render_template(
        "risk/target_risk.html",
        target=target,
        risk_records=risk_records,
        correlations=correlations,
    )


@risk_bp.route("/finding/<int:finding_id>", methods=["GET"])
@login_required
def finding_risk(finding_id: int):
    """Deep dive into CVSS v4.0 factors, priority explanation, and remediation for a finding."""
    vuln = db.session.get(Vulnerability, finding_id)
    if not vuln:
        abort(404)

    target = db.session.get(Target, vuln.target_id)
    if current_user.role != "ADMIN" and target and target.owner_id != current_user.id:
        abort(403)

    risk = RiskAssessment.query.filter_by(vulnerability_id=vuln.id).first()
    remediation = RemediationRecommendation.query.filter_by(vulnerability_id=vuln.id).first()

    # Generate on-the-fly preview if not already persisted
    if not risk:
        scored = CVSS4RiskEngine.score_vulnerability(vuln.title, vuln.vulnerability_type)
        p_lvl, p_rat = RiskPrioritizer.determine_priority(
            cvss_score=scored["cvss_score"],
            severity=scored["severity_rating"],
            confidence=vuln.confidence,
            environment=target.environment if target else "Production",
            vulnerability_name=vuln.title,
        )
        risk = {
            "cvss_version": scored["cvss_version"],
            "cvss_vector": scored["cvss_vector"],
            "cvss_score": scored["cvss_score"],
            "severity_rating": scored["severity_rating"],
            "operational_priority": p_lvl,
            "priority_rationale": p_rat,
            "get_scoring_factors": lambda: scored["scoring_factors"],
        }

    return render_template(
        "risk/finding_risk.html",
        vuln=vuln,
        target=target,
        risk=risk,
        remediation=remediation,
    )
