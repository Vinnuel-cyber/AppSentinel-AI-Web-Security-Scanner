from datetime import datetime, timezone
from collections import Counter
from app.models import (
    db,
    Target,
    Vulnerability,
    OWASPAssessment,
    OWASPFindingMapping,
    RiskAssessment,
    FindingCorrelation,
    RemediationRecommendation,
)
from app.security import (
    OWASPMapper,
    CVSS4RiskEngine,
    RiskPrioritizer,
    FindingCorrelator,
    RemediationEngine,
)


class OWASPServiceError(Exception):
    """Raised when OWASP or risk assessment fails validation or authorization."""
    pass


class OWASPService:
    """Enterprise OWASP Assessment and Risk Orchestration Service."""

    @classmethod
    def validate_target_access(cls, target: Target, user) -> None:
        """Validate target exists, is active, verified, and accessible by the user."""
        if not target:
            raise OWASPServiceError("Target not found.")

        if not target.is_active or target.deleted_at is not None:
            raise OWASPServiceError("Target has been deactivated or deleted.")

        if getattr(user, "role", None) != "ADMIN" and target.owner_id != user.id:
            raise OWASPServiceError("Unauthorized: You do not own this target.")

        if not target.is_verified or target.verification_status != "VERIFIED":
            raise OWASPServiceError("Target ownership is not verified.")

    @classmethod
    def run_target_assessment(cls, target_id: int, user_id: int) -> OWASPAssessment:
        """Execute full OWASP mapping, CVSS v4.0 scoring, correlation, and remediation analysis for a target."""
        target = db.session.get(Target, target_id)
        if not target:
            raise OWASPServiceError(f"Target #{target_id} not found.")

        # Fetch all findings for this target
        vulnerabilities = Vulnerability.query.filter_by(target_id=target.id).all()

        # Count repeat findings across endpoints for prioritization weighting
        vuln_counts = Counter(v.title.lower() for v in vulnerabilities)

        # Create assessment container
        assessment = OWASPAssessment(
            target_id=target.id,
            user_id=user_id,
            framework_name=OWASPMapper.FRAMEWORK_NAME,
            framework_version=OWASPMapper.FRAMEWORK_VERSION,
            total_findings_mapped=len(vulnerabilities),
        )
        db.session.add(assessment)
        db.session.flush()

        category_counts = Counter()
        priority_counts = Counter()
        scores = []

        # 1. Map Each Vulnerability
        for vuln in vulnerabilities:
            # A. OWASP Mapping
            mapped = OWASPMapper.map_finding(
                vulnerability_name=vuln.title,
                category=vuln.vulnerability_type,
                scanner_module=vuln.scanner_module,
                evidence=vuln.evidences.first().evidence_snippet if vuln.evidences.first() else "",
                cwe_id=vuln.cwe_id or "",
            )
            category_counts[mapped["primary_category_code"]] += 1

            # Update or create OWASPFindingMapping
            mapping_record = OWASPFindingMapping.query.filter_by(vulnerability_id=vuln.id).first()
            if not mapping_record:
                mapping_record = OWASPFindingMapping(
                    assessment_id=assessment.id,
                    vulnerability_id=vuln.id,
                    framework_version=mapped["framework_version"],
                    primary_category_code=mapped["primary_category_code"],
                    primary_category_name=mapped["primary_category_name"],
                    secondary_category_code=mapped["secondary_category_code"],
                    secondary_category_name=mapped["secondary_category_name"],
                    confidence=mapped["confidence"],
                    mapping_rationale=mapped["mapping_rationale"],
                )
                db.session.add(mapping_record)
            else:
                mapping_record.assessment_id = assessment.id
                mapping_record.primary_category_code = mapped["primary_category_code"]
                mapping_record.primary_category_name = mapped["primary_category_name"]
                mapping_record.secondary_category_code = mapped["secondary_category_code"]
                mapping_record.secondary_category_name = mapped["secondary_category_name"]
                mapping_record.confidence = mapped["confidence"]
                mapping_record.mapping_rationale = mapped["mapping_rationale"]

            # B. CVSS v4.0 Risk Scoring
            scored = CVSS4RiskEngine.score_vulnerability(
                vulnerability_name=vuln.title,
                category=vuln.vulnerability_type,
            )
            scores.append(scored["cvss_score"])

            # C. Operational Prioritization
            repeat_c = vuln_counts.get(vuln.title.lower(), 1)
            p_level, p_rationale = RiskPrioritizer.determine_priority(
                cvss_score=scored["cvss_score"],
                severity=scored["severity_rating"],
                confidence=vuln.confidence,
                environment=target.environment,
                repeat_count=repeat_c,
                vulnerability_name=vuln.title,
            )
            priority_counts[p_level] += 1

            risk_rec = RiskAssessment.query.filter_by(vulnerability_id=vuln.id).first()
            if not risk_rec:
                risk_rec = RiskAssessment(
                    vulnerability_id=vuln.id,
                    target_id=target.id,
                    cvss_version=scored["cvss_version"],
                    cvss_vector=scored["cvss_vector"],
                    cvss_score=scored["cvss_score"],
                    severity_rating=scored["severity_rating"],
                    operational_priority=p_level,
                    priority_rationale=p_rationale,
                )
                risk_rec.set_scoring_factors(scored["scoring_factors"])
                db.session.add(risk_rec)
            else:
                risk_rec.cvss_version = scored["cvss_version"]
                risk_rec.cvss_vector = scored["cvss_vector"]
                risk_rec.cvss_score = scored["cvss_score"]
                risk_rec.severity_rating = scored["severity_rating"]
                risk_rec.operational_priority = p_level
                risk_rec.priority_rationale = p_rationale
                risk_rec.set_scoring_factors(scored["scoring_factors"])

            # D. Remediation Guidance
            rem_info = RemediationEngine.generate_recommendation(
                vulnerability_name=vuln.title,
                category=vuln.vulnerability_type,
                affected_url=vuln.affected_url,
                parameter=vuln.parameter or "",
            )
            rem_rec = RemediationRecommendation.query.filter_by(vulnerability_id=vuln.id).first()
            if not rem_rec:
                rem_rec = RemediationRecommendation(
                    vulnerability_id=vuln.id,
                    target_id=target.id,
                    vulnerability_name=rem_info["vulnerability_name"],
                    affected_component=rem_info["affected_component"],
                    risk_explanation=rem_info["risk_explanation"],
                    recommended_fix=rem_info["recommended_fix"],
                    secure_example=rem_info["secure_example"],
                    verification_steps=rem_info["verification_steps"],
                )
                rem_rec.set_references(rem_info["references"])
                db.session.add(rem_rec)
            else:
                rem_rec.vulnerability_name = rem_info["vulnerability_name"]
                rem_rec.affected_component = rem_info["affected_component"]
                rem_rec.risk_explanation = rem_info["risk_explanation"]
                rem_rec.recommended_fix = rem_info["recommended_fix"]
                rem_rec.secure_example = rem_info["secure_example"]
                rem_rec.verification_steps = rem_info["verification_steps"]
                rem_rec.set_references(rem_info["references"])

        # 2. Correlate Findings
        correlations = FindingCorrelator.correlate_target_findings(vulnerabilities, target.id)
        for corr in correlations:
            corr_entry = FindingCorrelation(
                target_id=target.id,
                assessment_id=assessment.id,
                source_finding_id=corr["source_finding_id"],
                target_finding_id=corr["target_finding_id"],
                correlation_type=corr["correlation_type"],
                explanation=corr["explanation"],
            )
            db.session.add(corr_entry)

        # 3. Finalize Assessment Summary
        top_cat = category_counts.most_common(1)[0][0] if category_counts else "None"
        assessment.top_category = f"{top_cat} ({OWASPMapper.CATEGORIES.get(top_cat, 'None')})" if top_cat in OWASPMapper.CATEGORIES else top_cat
        summary_payload = {
            "category_distribution": dict(category_counts),
            "priority_distribution": dict(priority_counts),
            "max_cvss_score": max(scores) if scores else 0.0,
            "avg_cvss_score": round(sum(scores) / len(scores), 1) if scores else 0.0,
            "correlations_detected": len(correlations),
        }
        assessment.set_summary(summary_payload)
        db.session.commit()

        return assessment
