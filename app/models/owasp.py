from datetime import datetime, timezone
import json
from . import db


class OWASPAssessment(db.Model):
    __tablename__ = "owasp_assessments"

    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)

    framework_name = db.Column(db.String(64), default="OWASP Top 10", nullable=False)
    framework_version = db.Column(db.String(32), default="2025", nullable=False)

    total_findings_mapped = db.Column(db.Integer, default=0, nullable=False)
    top_category = db.Column(db.String(120), nullable=True)
    summary_data = db.Column(db.Text, nullable=True)  # JSON-encoded category counts & stats

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    mappings = db.relationship("OWASPFindingMapping", backref="assessment", lazy="dynamic", cascade="all, delete-orphan")
    correlations = db.relationship("FindingCorrelation", backref="assessment", lazy="dynamic", cascade="all, delete-orphan")

    def get_summary(self) -> dict:
        if not self.summary_data:
            return {}
        try:
            return json.loads(self.summary_data)
        except (ValueError, TypeError):
            return {}

    def set_summary(self, data: dict) -> None:
        self.summary_data = json.dumps(data) if data else "{}"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "target_id": self.target_id,
            "user_id": self.user_id,
            "scan_id": self.scan_id,
            "framework_name": self.framework_name,
            "framework_version": self.framework_version,
            "total_findings_mapped": self.total_findings_mapped,
            "top_category": self.top_category,
            "summary": self.get_summary(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class OWASPFindingMapping(db.Model):
    __tablename__ = "owasp_finding_mappings"

    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey("owasp_assessments.id", ondelete="CASCADE"), nullable=True, index=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)

    framework_version = db.Column(db.String(32), default="2025", nullable=False)
    primary_category_code = db.Column(db.String(16), nullable=False, index=True)  # e.g., A03:2021
    primary_category_name = db.Column(db.String(120), nullable=False)  # e.g., Injection

    secondary_category_code = db.Column(db.String(16), nullable=True)
    secondary_category_name = db.Column(db.String(120), nullable=True)

    confidence = db.Column(db.String(20), default="HIGH", nullable=False)  # HIGH, MEDIUM, LOW
    mapping_rationale = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationship to vulnerability
    vulnerability = db.relationship("Vulnerability", backref=db.backref("owasp_mapping", uselist=False, cascade="all, delete-orphan"))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "assessment_id": self.assessment_id,
            "vulnerability_id": self.vulnerability_id,
            "framework_version": self.framework_version,
            "primary_category_code": self.primary_category_code,
            "primary_category_name": self.primary_category_name,
            "secondary_category_code": self.secondary_category_code,
            "secondary_category_name": self.secondary_category_name,
            "confidence": self.confidence,
            "mapping_rationale": self.mapping_rationale,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class RiskAssessment(db.Model):
    __tablename__ = "risk_assessments"

    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)

    cvss_version = db.Column(db.String(10), default="4.0", nullable=False)
    cvss_vector = db.Column(db.String(150), nullable=False)
    cvss_score = db.Column(db.Float, default=0.0, nullable=False, index=True)
    severity_rating = db.Column(db.String(20), default="None", nullable=False, index=True)  # None, Low, Medium, High, Critical

    operational_priority = db.Column(db.String(10), default="P3", nullable=False, index=True)  # P1, P2, P3, P4, P5
    priority_rationale = db.Column(db.Text, nullable=False)
    scoring_factors = db.Column(db.Text, nullable=True)  # JSON explanation of metric selections

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    vulnerability = db.relationship("Vulnerability", backref=db.backref("risk_assessment", uselist=False, cascade="all, delete-orphan"))

    def get_scoring_factors(self) -> dict:
        if not self.scoring_factors:
            return {}
        try:
            return json.loads(self.scoring_factors)
        except (ValueError, TypeError):
            return {}

    def set_scoring_factors(self, data: dict) -> None:
        self.scoring_factors = json.dumps(data) if data else "{}"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "vulnerability_id": self.vulnerability_id,
            "target_id": self.target_id,
            "cvss_version": self.cvss_version,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "severity_rating": self.severity_rating,
            "operational_priority": self.operational_priority,
            "priority_rationale": self.priority_rationale,
            "scoring_factors": self.get_scoring_factors(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class FindingCorrelation(db.Model):
    __tablename__ = "finding_correlations"

    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey("owasp_assessments.id", ondelete="CASCADE"), nullable=True, index=True)

    source_finding_id = db.Column(db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    target_finding_id = db.Column(db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)

    correlation_type = db.Column(db.String(64), nullable=False)  # synergistic_vector, co_located_endpoint, repeated_flaw, diagnostic_exposure
    explanation = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    source_finding = db.relationship("Vulnerability", foreign_keys=[source_finding_id])
    target_finding = db.relationship("Vulnerability", foreign_keys=[target_finding_id])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "target_id": self.target_id,
            "assessment_id": self.assessment_id,
            "source_finding_id": self.source_finding_id,
            "target_finding_id": self.target_finding_id,
            "correlation_type": self.correlation_type,
            "explanation": self.explanation,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class RemediationRecommendation(db.Model):
    __tablename__ = "remediation_recommendations"

    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)

    vulnerability_name = db.Column(db.String(255), nullable=False)
    affected_component = db.Column(db.String(512), nullable=False)
    risk_explanation = db.Column(db.Text, nullable=False)
    recommended_fix = db.Column(db.Text, nullable=False)
    secure_example = db.Column(db.Text, nullable=True)
    verification_steps = db.Column(db.Text, nullable=False)
    references_data = db.Column(db.Text, nullable=True)  # JSON array of URLs / docs

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationship
    vulnerability = db.relationship("Vulnerability", backref=db.backref("remediation_details", uselist=False, cascade="all, delete-orphan"))

    def get_references(self) -> list:
        if not self.references_data:
            return []
        try:
            return json.loads(self.references_data)
        except (ValueError, TypeError):
            return []

    def set_references(self, refs: list) -> None:
        self.references_data = json.dumps(refs) if refs else "[]"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "vulnerability_id": self.vulnerability_id,
            "target_id": self.target_id,
            "vulnerability_name": self.vulnerability_name,
            "affected_component": self.affected_component,
            "risk_explanation": self.risk_explanation,
            "recommended_fix": self.recommended_fix,
            "secure_example": self.secure_example,
            "verification_steps": self.verification_steps,
            "references": self.get_references(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
