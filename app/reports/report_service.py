"""AppSentinel Report Management Service (V9).

Manages security report generation, storage, hash integrity verification,
multi-tenant authorization, safe downloads, and lifecycle management.
"""

import os
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from flask import current_app
from werkzeug.utils import secure_filename

from app.models import db, Target, Scan, Report, SecurityReport
from app.reports.data_collector import SecurityDataCollector
from app.reports.pdf_generator import PDFReportGenerator
from app.ai.context_builder import ContextBuilder


class ReportService:
    """Service orchestrating PDF report generation, secure storage, and downloads."""

    VALID_REPORT_TYPES = {"COMPLETE", "VULN_DETAIL", "EXECUTIVE"}

    @classmethod
    def get_report_storage_dir(cls) -> Path:
        """Resolve and verify reports storage directory."""
        if current_app:
            folder = Path(current_app.config.get("REPORT_FOLDER", Path(current_app.root_path) / ".." / "reports"))
        else:
            folder = Path(os.getcwd()) / "reports"
        folder.mkdir(parents=True, exist_ok=True)
        return folder.resolve()

    @classmethod
    def is_safe_path(cls, file_path: Path, base_dir: Path) -> bool:
        """Verify that resolved file path is strictly within base directory."""
        try:
            resolved_file = file_path.resolve()
            resolved_base = base_dir.resolve()
            return str(resolved_file).startswith(str(resolved_base))
        except Exception:
            return False

    @classmethod
    def generate_report(
        cls,
        user_id: int,
        scan_id: int,
        target_id: Optional[int] = None,
        report_type: str = "COMPLETE",
        is_admin: bool = False,
    ) -> Tuple[bool, Optional[Report], str]:
        """Generate, persist, and index a professional PDF assessment report.

        Returns:
            (success, report_record, message)
        """
        # Validate report type
        rpt_type = report_type.upper().strip()
        if rpt_type not in cls.VALID_REPORT_TYPES:
            return False, None, f"Invalid report type '{report_type}'. Must be COMPLETE, VULN_DETAIL, or EXECUTIVE."

        # Verify Scan and Target existence
        scan = Scan.query.filter_by(id=scan_id).first()
        if not scan:
            return False, None, "Scan not found."

        resolved_target_id = target_id or scan.target_id
        target = Target.query.filter_by(id=resolved_target_id).first()
        if not target or not target.is_active:
            return False, None, "Target not found or inactive."

        # Enforce multi-tenant ownership
        if not is_admin:
            if target.owner_id != user_id or scan.user_id != user_id:
                return False, None, "Unauthorized access to target or scan records."

        # Collect assessment data
        assessment_data = SecurityDataCollector.collect_assessment_data(
            scan_id=scan.id,
            target_id=target.id,
        )
        if not assessment_data:
            return False, None, "Failed to assemble assessment data for scan."

        # Compile PDF
        try:
            generator = PDFReportGenerator(assessment_data=assessment_data, report_type=rpt_type)
            pdf_bytes = generator.build_pdf()
        except Exception as ex:
            return False, None, f"PDF compilation error: {str(ex)}"

        # Calculate SHA-256 file hash
        file_hash = hashlib.sha256(pdf_bytes).hexdigest()
        file_size = len(pdf_bytes)

        # Generate safe filename
        clean_target_name = secure_filename(target.name.replace(" ", "_")) or "Target"
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_name = f"AppSentinel_{clean_target_name}_Scan{scan.id}_{rpt_type}_{timestamp}.pdf"

        # Determine safe destination path
        storage_dir = cls.get_report_storage_dir()
        dest_path = (storage_dir / safe_name).resolve()

        if not cls.is_safe_path(dest_path, storage_dir):
            return False, None, "Security violation: Invalid report destination path."

        # Write file
        try:
            with open(dest_path, "wb") as f:
                f.write(pdf_bytes)
        except Exception as ex:
            return False, None, f"Failed writing report to disk: {str(ex)}"

        # Titles by type
        title_map = {
            "COMPLETE": f"Complete Security Assessment - {target.name}",
            "VULN_DETAIL": f"Vulnerability Technical Details - {target.name}",
            "EXECUTIVE": f"Executive Security Posture - {target.name}",
        }
        title = title_map.get(rpt_type, f"Security Assessment - {target.name}")

        # Summary text
        metrics = assessment_data.get("metrics", {})
        summary = (
            f"{rpt_type} report for {target.name} (Scan #{scan.id}). "
            f"Evaluated {metrics.get('total_findings', 0)} findings with average CVSS {metrics.get('avg_cvss', 0.0)}."
        )

        # Persist report in database
        report = Report(
            scan_id=scan.id,
            target_id=target.id,
            user_id=user_id,
            title=title,
            report_type=rpt_type,
            report_filename=safe_name,
            report_status="COMPLETED",
            file_path=str(dest_path),
            file_format="PDF",
            file_hash=file_hash,
            file_size_bytes=file_size,
            summary=summary,
        )
        db.session.add(report)
        try:
            db.session.commit()
        except Exception as ex:
            db.session.rollback()
            # Clean up orphan file
            if dest_path.exists():
                dest_path.unlink()
            return False, None, f"Database transaction error: {str(ex)}"

        return True, report, "PDF report generated successfully."

    @classmethod
    def get_user_reports(cls, user_id: int, is_admin: bool = False, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve list of generated reports authorized for user."""
        query = Report.query
        if not is_admin:
            query = query.filter_by(user_id=user_id)

        reports = query.order_by(Report.created_at.desc()).limit(limit).all()
        return [r.to_dict() for r in reports]

    @classmethod
    def get_report_by_id(cls, report_id: int, user_id: int, is_admin: bool = False) -> Optional[Report]:
        """Retrieve specific report record verifying user ownership."""
        report = Report.query.filter_by(id=report_id).first()
        if not report:
            return None

        if is_admin:
            return report

        if report.user_id == user_id:
            return report

        # Fallback: check target ownership
        if report.target_id and ContextBuilder.check_target_access(report.target_id, user_id, is_admin=False):
            return report

        return None

    @classmethod
    def get_report_file_for_download(
        cls, report_id: int, user_id: int, is_admin: bool = False
    ) -> Tuple[bool, Optional[Path], Optional[str], str]:
        """Verify ownership and resolve safe file path for downloading.

        Returns:
            (success, file_path_or_none, filename_or_none, error_message)
        """
        report = cls.get_report_by_id(report_id, user_id, is_admin=is_admin)
        if not report:
            return False, None, None, "Report not found or unauthorized access."

        storage_dir = cls.get_report_storage_dir()
        file_path = Path(report.file_path).resolve()

        if not cls.is_safe_path(file_path, storage_dir):
            return False, None, None, "Path traversal security check failed."

        if not file_path.exists() or not file_path.is_file():
            return False, None, None, "Report file not found on storage disk."

        return True, file_path, report.report_filename or file_path.name, ""

    @classmethod
    def delete_report(cls, report_id: int, user_id: int, is_admin: bool = False) -> Tuple[bool, str]:
        """Delete report record and remove physical file from disk."""
        report = cls.get_report_by_id(report_id, user_id, is_admin=is_admin)
        if not report:
            return False, "Report not found or unauthorized access."

        # Physical file removal with path traversal check
        storage_dir = cls.get_report_storage_dir()
        if report.file_path:
            file_path = Path(report.file_path).resolve()
            if cls.is_safe_path(file_path, storage_dir) and file_path.exists():
                try:
                    file_path.unlink()
                except Exception as ex:
                    current_app.logger.warning("Failed removing report file %s: %s", file_path, ex)

        db.session.delete(report)
        try:
            db.session.commit()
            return True, "Report deleted successfully."
        except Exception as ex:
            db.session.rollback()
            return False, f"Failed to delete report: {str(ex)}"
