"""AppSentinel Context Builder for AI Security Analyst (V8).

Extracts, sanitizes, and structures database context for:
1. Vulnerability Finding Analysis.
2. Target Security Posture Summaries.
3. Natural-language Security Chat grounded in authorized scan results.

Strictly enforces multi-tenant authorization and RBAC:
Non-admin users can ONLY access targets, scans, and vulnerabilities they own.
"""

from typing import Optional, Dict, Any, List
from app.models import db
from app.models.vulnerability import Vulnerability, VulnerabilityEvidence
from app.models.target import Target
from app.models.scan import Scan


class ContextBuilder:
    """Safely queries and formats database entities for AI consumption with RBAC checks."""

    @classmethod
    def check_target_access(cls, target_id: int, user_id: int, is_admin: bool = False) -> bool:
        """Verify that user has authorized access to the target."""
        target = Target.query.filter_by(id=target_id).first()
        if not target or not target.is_active:
            return False
        if is_admin:
            return True
        return target.owner_id == user_id

    @classmethod
    def check_finding_access(cls, finding_id: int, user_id: int, is_admin: bool = False) -> bool:
        """Verify that user has authorized access to the vulnerability finding."""
        finding = Vulnerability.query.filter_by(id=finding_id).first()
        if not finding:
            return False
        if is_admin:
            return True

        # Finding may have direct target_id or via scan
        target_id = finding.target_id
        if not target_id and finding.scan_id:
            scan = Scan.query.filter_by(id=finding.scan_id).first()
            if scan:
                target_id = scan.target_id

        if not target_id:
            return False

        return cls.check_target_access(target_id, user_id, is_admin=is_admin)

    @classmethod
    def get_finding_context(
        cls, finding_id: int, user_id: int, is_admin: bool = False
    ) -> Optional[Dict[str, Any]]:
        """Extract and assemble finding metadata, target info, and scanned evidence."""
        finding = Vulnerability.query.filter_by(id=finding_id).first()
        if not finding:
            return None

        # Verify authorization
        if not cls.check_finding_access(finding_id, user_id, is_admin=is_admin):
            return None

        # Resolve Target
        target = None
        if finding.target_id:
            target = Target.query.filter_by(id=finding.target_id).first()
        elif finding.scan_id:
            scan = Scan.query.filter_by(id=finding.scan_id).first()
            if scan:
                target = Target.query.filter_by(id=scan.target_id).first()

        # Gather evidence snippets
        evidences = VulnerabilityEvidence.query.filter_by(vulnerability_id=finding.id).all()
        evidence_texts: List[str] = []
        for ev in evidences:
            parts = []
            if ev.payload:
                parts.append(f"Payload: {ev.payload}")
            if ev.evidence_snippet:
                parts.append(f"Snippet: {ev.evidence_snippet}")
            if ev.request_dump:
                parts.append(f"Request: {ev.request_dump[:500]}")
            if ev.response_dump:
                parts.append(f"Response: {ev.response_dump[:500]}")
            if parts:
                evidence_texts.append("\n".join(parts))

        combined_evidence = "\n---\n".join(evidence_texts) if evidence_texts else ""

        return {
            "id": finding.id,
            "target_id": target.id if target else None,
            "target_name": target.name if target else "Unknown Target",
            "target_url": target.target_url if target else "",
            "title": finding.title or finding.vulnerability_name,
            "category": finding.vulnerability_type or finding.category,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "cvss_score": finding.cvss_score,
            "cvss_vector": finding.cvss_vector or "",
            "owasp_category": finding.owasp_category or "A00:2025-Unknown",
            "cwe_id": finding.cwe_id or "CWE-Unknown",
            "affected_url": finding.affected_url,
            "parameter": finding.parameter or "",
            "http_method": finding.http_method or "GET",
            "description": finding.description or "",
            "scanner_module": finding.scanner_module or "vulnerability_manager",
            "evidence": combined_evidence,
            "status": finding.status,
            "created_at": finding.created_at.isoformat() if finding.created_at else None,
        }

    @classmethod
    def get_target_context(
        cls, target_id: int, user_id: int, is_admin: bool = False
    ) -> Optional[Dict[str, Any]]:
        """Extract target security posture, scan history, and vulnerability breakdown."""
        target = Target.query.filter_by(id=target_id).first()
        if not target or not target.is_active:
            return None

        if not is_admin and target.owner_id != user_id:
            return None

        # Fetch findings for this target
        findings = (
            Vulnerability.query.filter(
                (Vulnerability.target_id == target.id)
                | (
                    Vulnerability.scan_id.in_(
                        db.session.query(Scan.id).filter(Scan.target_id == target.id)
                    )
                )
            )
            .order_by(Vulnerability.cvss_score.desc())
            .all()
        )

        critical_count = sum(1 for f in findings if f.severity.upper() == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity.upper() == "HIGH")
        medium_count = sum(1 for f in findings if f.severity.upper() == "MEDIUM")
        low_count = sum(1 for f in findings if f.severity.upper() == "LOW")
        info_count = sum(1 for f in findings if f.severity.upper() in ["INFORMATIONAL", "INFO"])

        avg_cvss = (
            round(sum(f.cvss_score for f in findings) / len(findings), 1)
            if findings
            else 0.0
        )

        top_findings = []
        for f in findings[:10]:
            top_findings.append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "owasp_category": f.owasp_category,
                "affected_url": f.affected_url,
            })

        return {
            "id": target.id,
            "name": target.name,
            "target_url": target.target_url,
            "environment": target.environment,
            "is_verified": target.is_verified,
            "verification_status": target.verification_status,
            "findings_summary": {
                "total": len(findings),
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
                "info": info_count,
                "avg_cvss": avg_cvss,
            },
            "top_findings": top_findings,
        }

    @classmethod
    def get_chat_context(
        cls, user_id: int, target_id: Optional[int] = None, is_admin: bool = False
    ) -> str:
        """Format authorized database records into concise text for natural-language Q&A grounding."""
        # Query authorized targets
        target_query = Target.query.filter_by(is_active=True)
        if not is_admin:
            target_query = target_query.filter_by(owner_id=user_id)

        if target_id:
            target_query = target_query.filter_by(id=target_id)

        targets = target_query.all()
        if not targets:
            return "No authorized targets found in database."

        lines: List[str] = [f"AUTHORIZED TARGET APPLICATIONS ({len(targets)}):"]
        target_ids = [t.id for t in targets]

        for t in targets:
            lines.append(f"- Target #{t.id}: {t.name} ({t.target_url}) | Env: {t.environment} | Verified: {t.is_verified}")

        # Query findings for these targets
        findings = (
            Vulnerability.query.filter(
                (Vulnerability.target_id.in_(target_ids))
                | (
                    Vulnerability.scan_id.in_(
                        db.session.query(Scan.id).filter(Scan.target_id.in_(target_ids))
                    )
                )
            )
            .order_by(Vulnerability.cvss_score.desc())
            .limit(25)
            .all()
        )

        lines.append(f"\nVERIFIED FINDINGS IN USER SCOPE ({len(findings)} latest/highest risk):")
        if not findings:
            lines.append("No vulnerabilities currently recorded for these targets.")
        else:
            for f in findings:
                lines.append(
                    f"- Finding #{f.id}: [{f.severity}] {f.title} (CVSS {f.cvss_score}, OWASP: {f.owasp_category}) "
                    f"at {f.affected_url} [Param: {f.parameter or 'N/A'}] (Status: {f.status})"
                )

        return "\n".join(lines)
