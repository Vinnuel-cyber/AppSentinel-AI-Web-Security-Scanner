"""AppSentinel Security Data Collector for PDF Reports (V9).

Assembles, verifies, and sanitizes database records for report generation:
- Target & Scan telemetry.
- Findings and severity breakdown.
- CVSS v4.0 scores and canonical vector representations.
- OWASP Top 10:2025 and CWE taxonomic mappings.
- Evidence dumps with strict credential and secret redaction.
- Deterministic remediation blueprints and V8 AI Analyst insights.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from app.models import db, Target, Scan, Vulnerability, VulnerabilityEvidence
from app.models.vulnerability import AIAnalysis
from app.models.owasp import OWASPAssessment, RiskAssessment
from app.ai.prompt_manager import PromptManager


class SecurityDataCollector:
    """Safely extracts and shapes security assessment data for PDF generation."""

    @classmethod
    def collect_assessment_data(cls, scan_id: int, target_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Query and synthesize comprehensive assessment metrics for a scan."""
        scan = Scan.query.filter_by(id=scan_id).first()
        if not scan:
            return None

        # Resolve Target
        t_id = target_id or scan.target_id
        target = Target.query.filter_by(id=t_id).first()
        if not target:
            return None

        # Fetch vulnerabilities for this scan
        findings_query = Vulnerability.query.filter_by(scan_id=scan.id).order_by(
            Vulnerability.cvss_score.desc(), Vulnerability.id.asc()
        ).all()

        findings_data: List[Dict[str, Any]] = []
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFORMATIONAL": 0,
        }

        owasp_distribution: Dict[str, int] = {}
        total_cvss = 0.0

        for f in findings_query:
            sev = (f.severity or "INFORMATIONAL").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["INFORMATIONAL"] += 1

            total_cvss += (f.cvss_score or 0.0)

            # OWASP categorization
            owasp_cat = f.owasp_category or "A00:2025-Unknown"
            owasp_distribution[owasp_cat] = owasp_distribution.get(owasp_cat, 0) + 1

            # Evidence retrieval & redaction
            evidences = VulnerabilityEvidence.query.filter_by(vulnerability_id=f.id).all()
            ev_list = []
            for ev in evidences:
                clean_payload = PromptManager.sanitize_untrusted_text(ev.payload, max_len=500) if ev.payload else ""
                clean_snippet = PromptManager.sanitize_untrusted_text(ev.evidence_snippet, max_len=800) if ev.evidence_snippet else ""
                clean_req = PromptManager.sanitize_untrusted_text(ev.request_dump, max_len=600) if ev.request_dump else ""
                clean_res = PromptManager.sanitize_untrusted_text(ev.response_dump, max_len=600) if ev.response_dump else ""
                if clean_payload or clean_snippet or clean_req or clean_res:
                    ev_list.append({
                        "payload": clean_payload,
                        "snippet": clean_snippet,
                        "request": clean_req,
                        "response": clean_res,
                    })

            # Check for V8 AI Analysis record
            ai_rec = AIAnalysis.query.filter_by(vulnerability_id=f.id).first()
            ai_data = None
            if ai_rec:
                ai_data = {
                    "is_fallback": ai_rec.is_fallback,
                    "provider": ai_rec.provider,
                    "model_name": ai_rec.model_name,
                    "ai_confidence": ai_rec.ai_confidence,
                    "explanation": PromptManager.sanitize_untrusted_text(ai_rec.explanation, max_len=2000),
                    "root_cause": PromptManager.sanitize_untrusted_text(ai_rec.root_cause, max_len=1000),
                    "remediation": PromptManager.sanitize_untrusted_text(ai_rec.recommended_remediation, max_len=2000),
                    "code_example": PromptManager.sanitize_untrusted_text(ai_rec.secure_coding_example, max_len=2000),
                    "verification_steps": PromptManager.sanitize_untrusted_text(ai_rec.verification_steps, max_len=1500),
                }

            clean_title = PromptManager.sanitize_untrusted_text(f.title, max_len=200) or "Security Vulnerability"
            clean_desc = PromptManager.sanitize_untrusted_text(f.description, max_len=2000) or "No scanner description provided."
            clean_remed = PromptManager.sanitize_untrusted_text(f.remediation, max_len=2000) or "Implement input validation and defense-in-depth controls."

            findings_data.append({
                "id": f.id,
                "title": clean_title,
                "category": f.vulnerability_type or "General",
                "severity": sev,
                "confidence": f.confidence or "MEDIUM",
                "cvss_score": f.cvss_score or 0.0,
                "cvss_vector": f.cvss_vector or "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
                "owasp_category": owasp_cat,
                "cwe_id": f.cwe_id or "CWE-Unknown",
                "affected_url": PromptManager.sanitize_untrusted_text(f.affected_url, max_len=200),
                "parameter": PromptManager.sanitize_untrusted_text(f.parameter, max_len=100) if f.parameter else "N/A",
                "http_method": f.http_method or "GET",
                "description": clean_desc,
                "remediation": clean_remed,
                "evidence_list": ev_list,
                "ai_analysis": ai_data,
            })

        num_findings = len(findings_data)
        avg_cvss = round(total_cvss / num_findings, 1) if num_findings > 0 else 0.0

        # Posture assessment score
        if severity_counts["CRITICAL"] > 0:
            posture_rating = "CRITICAL RISK"
        elif severity_counts["HIGH"] > 1:
            posture_rating = "HIGH RISK"
        elif severity_counts["HIGH"] == 1 or severity_counts["MEDIUM"] > 2:
            posture_rating = "MODERATE RISK"
        elif severity_counts["MEDIUM"] > 0 or severity_counts["LOW"] > 0:
            posture_rating = "LOW RISK"
        else:
            posture_rating = "SECURE / INFORMATIONAL"

        # Unique report reference ID
        now_utc = datetime.now(timezone.utc)
        report_id = f"AS-RPT-{now_utc.strftime('%Y%m%d')}-{scan.id:04d}"

        return {
            "report_reference": report_id,
            "generated_at_utc": now_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "target": {
                "id": target.id,
                "name": target.name,
                "url": target.target_url,
                "domain": target.domain,
                "environment": target.environment,
                "is_verified": target.is_verified,
                "verification_method": target.verification_method,
            },
            "scan": {
                "id": scan.id,
                "scan_type": scan.scan_type.upper(),
                "status": scan.status.upper(),
                "risk_score": scan.risk_score,
                "overall_risk": scan.overall_risk,
                "duration_seconds": scan.duration_seconds,
                "started_at": scan.started_at.strftime("%Y-%m-%d %H:%M:%S UTC") if scan.started_at else "N/A",
                "completed_at": scan.completed_at.strftime("%Y-%m-%d %H:%M:%S UTC") if scan.completed_at else "N/A",
            },
            "metrics": {
                "total_findings": num_findings,
                "severity_counts": severity_counts,
                "avg_cvss": avg_cvss,
                "posture_rating": posture_rating,
                "owasp_distribution": owasp_distribution,
            },
            "findings": findings_data,
        }
