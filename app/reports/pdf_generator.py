"""AppSentinel Professional PDF Report Generator (V9).

Implements professional, publication-quality cybersecurity assessment reports
using ReportLab:
- Report Type A: Complete Security Assessment Report
- Report Type B: Vulnerability Detail Report
- Report Type C: Executive Summary Report
- Two-pass NumberedCanvas for dynamic "Page X of Y" and confidentiality banners.
- Strict layout discipline: auto-wrapping paragraphs, controlled table column widths,
  and page break management to prevent text clipping or overflow.
"""

import io
import html
from typing import Dict, Any, List
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
    HRFlowable,
)

from app.reports.pdf_theme import PDFTheme
from app.reports.canvas_helpers import NumberedCanvas


def _escape(val: Any) -> str:
    """Safely escape text for ReportLab XML/HTML Paragraph elements."""
    if val is None:
        return ""
    return html.escape(str(val), quote=False)


class PDFReportGenerator:
    """Generates structured, professional PDF security reports from assessment records."""

    PAGE_WIDTH = 504  # 612 - 54*2 printable width in points

    def __init__(self, assessment_data: Dict[str, Any], report_type: str = "COMPLETE"):
        self.data = assessment_data
        self.report_type = report_type.upper()
        self.styles = PDFTheme.get_stylesheet()

    def build_pdf(self) -> bytes:
        """Construct flowables and compile into a complete PDF byte string."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54,
        )

        story = []

        # 1. Professional Cover Page
        story.extend(self._build_cover_page())
        story.append(PageBreak())

        # 2. Executive Summary & Posture Scorecard
        story.extend(self._build_executive_summary())

        # 3. Scope & Target Environment
        story.extend(self._build_scope_section())

        # 4. Severity Distribution & OWASP 2025 Matrix
        story.extend(self._build_risk_matrix_section())

        # 5. Detailed Findings (Included in COMPLETE and VULN_DETAIL)
        if self.report_type in ("COMPLETE", "VULN_DETAIL"):
            story.append(PageBreak())
            story.extend(self._build_detailed_findings())

        # 6. Conclusion & Remediation Roadmap
        story.extend(self._build_conclusion_section())

        # Build document using NumberedCanvas for two-pass running header/footer
        doc.build(story, canvasmaker=NumberedCanvas)
        buffer.seek(0)
        return buffer.getvalue()

    def _build_cover_page(self) -> List[Any]:
        """Generate high-impact cover page."""
        story = []
        target = self.data.get("target", {})
        metrics = self.data.get("metrics", {})

        # Top spacing
        story.append(Spacer(1, 40))

        # Brand Supertitle
        story.append(Paragraph("APPSENTINEL APPLICATION SECURITY PLATFORM", self.styles["CoverSubtitle"]))
        story.append(Spacer(1, 8))

        # Main Report Title based on type
        title_text = {
            "COMPLETE": "Comprehensive Web Application Security Assessment",
            "VULN_DETAIL": "Vulnerability Technical Diagnostics & Remediation",
            "EXECUTIVE": "Executive Cybersecurity Posture Summary",
        }.get(self.report_type, "Web Application Security Report")

        # Inverted colored block for cover banner
        banner_table = Table(
            [[Paragraph(title_text, self.styles["CoverTitle"])]],
            colWidths=[self.PAGE_WIDTH],
        )
        banner_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), PDFTheme.PRIMARY),
            ("TOPPADDING", (0, 0), (-1, -1), 22),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 22),
            ("LEFTPADDING", (0, 0), (-1, -1), 18),
            ("RIGHTPADDING", (0, 0), (-1, -1), 18),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(banner_table)
        story.append(Spacer(1, 15))

        # Sub-badge line
        type_badge = {
            "COMPLETE": "FULL SCOPE TECHNICAL AUDIT REPORT",
            "VULN_DETAIL": "DEEP DIVE DEFECT SPECIFICATIONS",
            "EXECUTIVE": "EXECUTIVE RISK & COMPLIANCE SYNTHESIS",
        }.get(self.report_type, "SECURITY ASSESSMENT")

        badge_data = [[
            Paragraph(f"<b>REPORT TYPE:</b> {type_badge}", self.styles["TableCellBold"]),
            Paragraph(f"<b>FRAMEWORK:</b> OWASP 2025 / CVSS v4.0", self.styles["TableCellBold"]),
        ]]
        badge_table = Table(badge_data, colWidths=[270, 234])
        badge_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), PDFTheme.BG_LIGHT),
            ("BOX", (0, 0), (-1, -1), 1, PDFTheme.BORDER_LIGHT),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ]))
        story.append(badge_table)
        story.append(Spacer(1, 40))

        # Metadata Details Block
        meta_rows = [
            [
                Paragraph("Target Name:", self.styles["TableCellBold"]),
                Paragraph(_escape(target.get("name", "Unknown")), self.styles["TableCell"]),
            ],
            [
                Paragraph("Target URL:", self.styles["TableCellBold"]),
                Paragraph(_escape(target.get("url", "N/A")), self.styles["TableCell"]),
            ],
            [
                Paragraph("Environment:", self.styles["TableCellBold"]),
                Paragraph(_escape(target.get("environment", "Production")), self.styles["TableCell"]),
            ],
            [
                Paragraph("Assessment Scope:", self.styles["TableCellBold"]),
                Paragraph("Authorized Non-Destructive Vulnerability Assessment", self.styles["TableCell"]),
            ],
            [
                Paragraph("Overall Risk Rating:", self.styles["TableCellBold"]),
                Paragraph(
                    f"<b><font color='{PDFTheme.get_severity_color(metrics.get('posture_rating', '').split()[0]).hexval()}'>{_escape(metrics.get('posture_rating', 'MODERATE'))}</font></b>",
                    self.styles["TableCell"],
                ),
            ],
            [
                Paragraph("Report Reference ID:", self.styles["TableCellBold"]),
                Paragraph(_escape(self.data.get("report_reference", "AS-RPT-0000")), self.styles["TableCell"]),
            ],
            [
                Paragraph("Generation Date (UTC):", self.styles["TableCellBold"]),
                Paragraph(_escape(self.data.get("generated_at_utc", "")), self.styles["TableCell"]),
            ],
        ]
        meta_table = Table(meta_rows, colWidths=[150, 354])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.white),
            ("BOX", (0, 0), (-1, -1), 1, PDFTheme.BORDER_LIGHT),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, PDFTheme.BORDER_LIGHT),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ]))
        story.append(meta_table)

        story.append(Spacer(1, 60))

        # Confidentiality Notice Block
        disclaimer_text = (
            "<b>CONFIDENTIALITY NOTICE:</b> The information contained in this security assessment report is strictly "
            "confidential and intended solely for the authorized stakeholders of the target organization. This document "
            "contains detailed technical findings and potential exploit indicators. Unauthorized distribution, reproduction, "
            "or dissemination of this report is strictly prohibited under cybersecurity non-disclosure standards."
        )
        disc_table = Table(
            [[Paragraph(disclaimer_text, self.styles["ReportCallout"])]],
            colWidths=[self.PAGE_WIDTH],
        )
        disc_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), PDFTheme.BG_LIGHT),
            ("BOX", (0, 0), (-1, -1), 0.5, PDFTheme.BORDER_LIGHT),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ]))
        story.append(disc_table)

        return story

    def _build_executive_summary(self) -> List[Any]:
        """Generate high-level executive summary and posture metrics."""
        story = []
        metrics = self.data.get("metrics", {})
        counts = metrics.get("severity_counts", {})
        target = self.data.get("target", {})
        scan = self.data.get("scan", {})

        story.append(Paragraph("1. Executive Summary", self.styles["ReportH1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=PDFTheme.BORDER_LIGHT, spaceAfter=8))

        summary_p1 = (
            f"AppSentinel completed an authorized security assessment against <b>{_escape(target.get('name'))}</b> "
            f"(<code>{_escape(target.get('url'))}</code>) utilizing deterministic vulnerability scanners, CVSS v4.0 risk metrics, "
            f"and OWASP Top 10:2025 taxonomy. The evaluation was conducted in non-destructive mode on "
            f"{_escape(self.data.get('generated_at_utc', 'the assessment window'))}."
        )
        story.append(Paragraph(summary_p1, self.styles["ReportBodyJustify"]))

        total_findings = metrics.get("total_findings", 0)
        summary_p2 = (
            f"During the assessment, AppSentinel identified a total of <b>{total_findings} security findings</b> "
            f"comprising <b>{counts.get('CRITICAL', 0)} Critical</b>, <b>{counts.get('HIGH', 0)} High</b>, "
            f"<b>{counts.get('MEDIUM', 0)} Medium</b>, <b>{counts.get('LOW', 0)} Low</b>, and "
            f"<b>{counts.get('INFORMATIONAL', 0)} Informational</b> defects. The aggregate target risk posture "
            f"is evaluated as <b>{_escape(metrics.get('posture_rating', 'MODERATE'))}</b> with an average CVSS v4.0 score of "
            f"<b>{metrics.get('avg_cvss', 0.0)} / 10.0</b>."
        )
        story.append(Paragraph(summary_p2, self.styles["ReportBodyJustify"]))
        story.append(Spacer(1, 8))

        # Scorecard Summary Table
        card_headers = [
            Paragraph("Posture Rating", self.styles["TableCellHeader"]),
            Paragraph("Total Findings", self.styles["TableCellHeader"]),
            Paragraph("Average CVSS", self.styles["TableCellHeader"]),
            Paragraph("Scan Execution Mode", self.styles["TableCellHeader"]),
        ]
        card_values = [
            Paragraph(f"<b><font color='{PDFTheme.get_severity_color(metrics.get('posture_rating', '').split()[0]).hexval()}'>{_escape(metrics.get('posture_rating', 'MODERATE'))}</font></b>", self.styles["TableCellCenter"]),
            Paragraph(f"<b>{total_findings}</b>", self.styles["TableCellCenter"]),
            Paragraph(f"<b>{metrics.get('avg_cvss', 0.0)}</b>", self.styles["TableCellCenter"]),
            Paragraph(f"<b>{_escape(scan.get('scan_type', 'PASSIVE'))}</b>", self.styles["TableCellCenter"]),
        ]
        card_table = Table([card_headers, card_values], colWidths=[130, 110, 110, 154])
        card_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PDFTheme.PRIMARY),
            ("BACKGROUND", (0, 1), (-1, 1), PDFTheme.BG_LIGHT),
            ("BOX", (0, 0), (-1, -1), 1, PDFTheme.BORDER_LIGHT),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, PDFTheme.BORDER_LIGHT),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("ALIGN", (0, 1), (-1, 1), "CENTER"),
        ]))
        story.append(card_table)
        story.append(Spacer(1, 14))

        return story

    def _build_scope_section(self) -> List[Any]:
        """Generate target environment and scan telemetry details."""
        story = []
        target = self.data.get("target", {})
        scan = self.data.get("scan", {})

        story.append(Paragraph("2. Scope & Target Environment", self.styles["ReportH1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=PDFTheme.BORDER_LIGHT, spaceAfter=8))

        scope_rows = [
            [Paragraph("Target Identifier:", self.styles["TableCellBold"]), Paragraph(f"Target #{_escape(target.get('id'))}", self.styles["TableCell"])],
            [Paragraph("Target Name:", self.styles["TableCellBold"]), Paragraph(_escape(target.get("name", "N/A")), self.styles["TableCell"])],
            [Paragraph("Target URL:", self.styles["TableCellBold"]), Paragraph(_escape(target.get("url", "N/A")), self.styles["TableCell"])],
            [Paragraph("Deployment Environment:", self.styles["TableCellBold"]), Paragraph(_escape(target.get("environment", "Production")), self.styles["TableCell"])],
            [Paragraph("Ownership Status:", self.styles["TableCellBold"]), Paragraph(f"Verified (Method: {_escape(target.get('verification_method', 'N/A'))})", self.styles["TableCell"])],
            [Paragraph("Scan Identifier:", self.styles["TableCellBold"]), Paragraph(f"Scan #{_escape(scan.get('id'))}", self.styles["TableCell"])],
            [Paragraph("Scan Execution Window:", self.styles["TableCellBold"]), Paragraph(f"{_escape(scan.get('started_at'))} to {_escape(scan.get('completed_at'))}", self.styles["TableCell"])],
            [Paragraph("Scan Duration:", self.styles["TableCellBold"]), Paragraph(f"{_escape(scan.get('duration_seconds', 0))} seconds", self.styles["TableCell"])],
        ]
        scope_table = Table(scope_rows, colWidths=[150, 354])
        scope_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), PDFTheme.BG_LIGHT),
            ("BOX", (0, 0), (-1, -1), 1, PDFTheme.BORDER_LIGHT),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, PDFTheme.BORDER_LIGHT),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(scope_table)
        story.append(Spacer(1, 14))

        return story

    def _build_risk_matrix_section(self) -> List[Any]:
        """Generate findings severity breakdown and OWASP 2025 matrix."""
        story = []
        metrics = self.data.get("metrics", {})
        counts = metrics.get("severity_counts", {})
        owasp_dist = metrics.get("owasp_distribution", {})

        story.append(Paragraph("3. Risk Distribution & OWASP Top 10:2025 Matrix", self.styles["ReportH1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=PDFTheme.BORDER_LIGHT, spaceAfter=8))

        # Severity breakdown table with distinct colors
        sev_headers = [
            Paragraph("Critical", self.styles["TableCellHeader"]),
            Paragraph("High", self.styles["TableCellHeader"]),
            Paragraph("Medium", self.styles["TableCellHeader"]),
            Paragraph("Low", self.styles["TableCellHeader"]),
            Paragraph("Informational", self.styles["TableCellHeader"]),
        ]
        sev_counts = [
            Paragraph(f"<b><font color='{PDFTheme.CRITICAL.hexval()}'>{counts.get('CRITICAL', 0)}</font></b>", self.styles["TableCellCenter"]),
            Paragraph(f"<b><font color='{PDFTheme.HIGH.hexval()}'>{counts.get('HIGH', 0)}</font></b>", self.styles["TableCellCenter"]),
            Paragraph(f"<b><font color='{PDFTheme.MEDIUM.hexval()}'>{counts.get('MEDIUM', 0)}</font></b>", self.styles["TableCellCenter"]),
            Paragraph(f"<b><font color='{PDFTheme.LOW.hexval()}'>{counts.get('LOW', 0)}</font></b>", self.styles["TableCellCenter"]),
            Paragraph(f"<b><font color='{PDFTheme.INFO.hexval()}'>{counts.get('INFORMATIONAL', 0)}</font></b>", self.styles["TableCellCenter"]),
        ]
        sev_table = Table([sev_headers, sev_counts], colWidths=[100.8, 100.8, 100.8, 100.8, 100.8])
        sev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PDFTheme.SECONDARY),
            ("BACKGROUND", (0, 1), (-1, 1), PDFTheme.BG_LIGHT),
            ("BOX", (0, 0), (-1, -1), 1, PDFTheme.BORDER_LIGHT),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, PDFTheme.BORDER_LIGHT),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(sev_table)
        story.append(Spacer(1, 12))

        # OWASP Mapping Summary
        story.append(Paragraph("OWASP Top 10:2025 Categories Observed", self.styles["ReportH2"]))
        if owasp_dist:
            owasp_rows = [[
                Paragraph("OWASP 2025 Category", self.styles["TableCellHeader"]),
                Paragraph("Identified Findings", self.styles["TableCellHeader"]),
            ]]
            for cat, cnt in sorted(owasp_dist.items(), key=lambda x: x[1], reverse=True):
                owasp_rows.append([
                    Paragraph(_escape(cat), self.styles["TableCell"]),
                    Paragraph(str(cnt), self.styles["TableCellCenter"]),
                ])
            owasp_table = Table(owasp_rows, colWidths=[400, 104])
            owasp_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), PDFTheme.PRIMARY),
                ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PDFTheme.BG_LIGHT]),
                ("BOX", (0, 0), (-1, -1), 1, PDFTheme.BORDER_LIGHT),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, PDFTheme.BORDER_LIGHT),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ]))
            story.append(owasp_table)
        else:
            story.append(Paragraph("<i>No OWASP-mapped defects identified in this assessment.</i>", self.styles["ReportBody"]))

        story.append(Spacer(1, 14))
        return story

    def _build_detailed_findings(self) -> List[Any]:
        """Generate comprehensive findings with CVSS vectors, redacted evidence, and remediation."""
        story = []
        findings = self.data.get("findings", [])

        story.append(Paragraph("4. Detailed Technical Findings", self.styles["ReportH1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=PDFTheme.BORDER_LIGHT, spaceAfter=10))

        if not findings:
            story.append(Paragraph("<i>No vulnerabilities were detected during this assessment.</i>", self.styles["ReportBody"]))
            return story

        for idx, f in enumerate(findings, 1):
            sev_color = PDFTheme.get_severity_color(f["severity"])

            # Finding Header Card
            finding_header = [
                [
                    Paragraph(f"<b>#{idx}. {_escape(f['title'])}</b>", self.styles["TableCellHeader"]),
                    Paragraph(f"<b>{_escape(f['severity'])} (CVSS {_escape(f['cvss_score'])})</b>", self.styles["TableCellHeader"]),
                ]
            ]
            head_table = Table(finding_header, colWidths=[364, 140])
            head_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), sev_color),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]))

            # Metadata grid
            meta_rows = [
                [Paragraph("Affected Endpoint:", self.styles["TableCellBold"]), Paragraph(f"<code>{_escape(f['affected_url'])}</code>", self.styles["TableCell"])],
                [Paragraph("HTTP Method / Param:", self.styles["TableCellBold"]), Paragraph(f"{_escape(f['http_method'])} | Parameter: <code>{_escape(f['parameter'])}</code>", self.styles["TableCell"])],
                [Paragraph("OWASP 2025:", self.styles["TableCellBold"]), Paragraph(f"{_escape(f['owasp_category'])}", self.styles["TableCell"])],
                [Paragraph("CWE Taxonomy:", self.styles["TableCellBold"]), Paragraph(f"{_escape(f['cwe_id'])}", self.styles["TableCell"])],
                [Paragraph("CVSS v4.0 Vector:", self.styles["TableCellBold"]), Paragraph(f"<code>{_escape(f['cvss_vector'])}</code>", self.styles["TableCell"])],
                [Paragraph("Scanner Confidence:", self.styles["TableCellBold"]), Paragraph(f"{_escape(f['confidence'])} (Deterministic)", self.styles["TableCell"])],
            ]
            meta_table = Table(meta_rows, colWidths=[130, 374])
            meta_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), PDFTheme.BG_LIGHT),
                ("BOX", (0, 0), (-1, -1), 1, PDFTheme.BORDER_LIGHT),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, PDFTheme.BORDER_LIGHT),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ]))

            finding_flowables = [
                head_table,
                meta_table,
                Spacer(1, 6),
                Paragraph("<b>Technical Description:</b>", self.styles["ReportH3"]),
                Paragraph(_escape(f["description"]), self.styles["ReportBody"]),
            ]

            # Scanned Evidence
            if f["evidence_list"]:
                finding_flowables.append(Paragraph("<b>Observed Scanner Evidence (Redacted):</b>", self.styles["ReportH3"]))
                for ev in f["evidence_list"]:
                    if ev.get("payload"):
                        finding_flowables.append(Paragraph(f"<b>Probe Payload:</b> <code>{_escape(ev['payload'])}</code>", self.styles["ReportBody"]))
                    if ev.get("snippet"):
                        finding_flowables.append(Paragraph(_escape(ev["snippet"]), self.styles["ReportCode"]))

            # Remediation
            finding_flowables.append(Paragraph("<b>Remediation Guidance:</b>", self.styles["ReportH3"]))
            finding_flowables.append(Paragraph(_escape(f["remediation"]), self.styles["ReportBody"]))

            # V8 AI Security Analyst Insights (clearly labeled)
            if f.get("ai_analysis"):
                ai = f["ai_analysis"]
                provider_desc = "Offline Deterministic Fallback Engine" if ai["is_fallback"] else f"OpenAI ({_escape(ai['model_name'])})"
                disclaimer = f"<i>[AI Security Analyst Advisory – Provider: {provider_desc} | Confidence: {_escape(ai['ai_confidence'])}]</i>"
                finding_flowables.append(Spacer(1, 4))
                finding_flowables.append(Paragraph(disclaimer, self.styles["ReportCallout"]))
                if ai.get("root_cause"):
                    finding_flowables.append(Paragraph(f"<b>Root Cause:</b> {_escape(ai['root_cause'])}", self.styles["ReportBody"]))
                if ai.get("code_example"):
                    finding_flowables.append(Paragraph(_escape(ai["code_example"]), self.styles["ReportCode"]))
                if ai.get("verification_steps"):
                    finding_flowables.append(Paragraph(f"<b>Developer Verification Steps:</b> {_escape(ai['verification_steps'])}", self.styles["ReportBody"]))

            finding_flowables.append(Spacer(1, 14))
            story.append(KeepTogether(finding_flowables))

        return story

    def _build_conclusion_section(self) -> List[Any]:
        """Generate conclusion, operational remediation SLAs, and audit sign-off."""
        story = []
        metrics = self.data.get("metrics", {})

        story.append(Paragraph("5. Remediation Roadmap & Conclusion", self.styles["ReportH1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=PDFTheme.BORDER_LIGHT, spaceAfter=8))

        # Remediation SLA table
        sla_rows = [
            [Paragraph("Priority Tier", self.styles["TableCellHeader"]), Paragraph("Severity", self.styles["TableCellHeader"]), Paragraph("Recommended Remediation SLA", self.styles["TableCellHeader"])],
            [Paragraph("P1 - Immediate", self.styles["TableCellBold"]), Paragraph("Critical (9.0 - 10.0)", self.styles["TableCell"]), Paragraph("Within 24 to 48 Hours", self.styles["TableCell"])],
            [Paragraph("P2 - Urgent", self.styles["TableCellBold"]), Paragraph("High (7.0 - 8.9)", self.styles["TableCell"]), Paragraph("Within 7 Calendar Days", self.styles["TableCell"])],
            [Paragraph("P3 - Standard", self.styles["TableCellBold"]), Paragraph("Medium (4.0 - 6.9)", self.styles["TableCell"]), Paragraph("Within 30 Calendar Days", self.styles["TableCell"])],
            [Paragraph("P4 - Low Risk", self.styles["TableCellBold"]), Paragraph("Low (0.1 - 3.9)", self.styles["TableCell"]), Paragraph("Next Scheduled Release Cycle", self.styles["TableCell"])],
            [Paragraph("P5 - Informational", self.styles["TableCellBold"]), Paragraph("Informational (0.0)", self.styles["TableCell"]), Paragraph("Architectural Review / Best Practice", self.styles["TableCell"])],
        ]
        sla_table = Table(sla_rows, colWidths=[130, 160, 214])
        sla_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PDFTheme.PRIMARY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PDFTheme.BG_LIGHT]),
            ("BOX", (0, 0), (-1, -1), 1, PDFTheme.BORDER_LIGHT),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, PDFTheme.BORDER_LIGHT),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(sla_table)
        story.append(Spacer(1, 14))

        conclusion_text = (
            f"This security assessment concluded with an overall posture rating of <b>{_escape(metrics.get('posture_rating', 'MODERATE'))}</b>. "
            f"Remediation efforts should immediately prioritize confirmed critical and high severity defects. Following remediation, "
            f"a verification retest should be executed through the AppSentinel scanner to validate flaw closure."
        )
        story.append(Paragraph(conclusion_text, self.styles["ReportBodyJustify"]))

        return story
