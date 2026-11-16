"""AppSentinel Professional PDF Report Generator Package (V9).

Provides:
- PDFTheme: Typography, stylesheets, and enterprise colors.
- NumberedCanvas: Two-pass dynamic page numbering and header/footer rendering.
- SecurityDataCollector: Database record synthesis and secret redaction.
- PDFReportGenerator: Flowables document builder.
- ReportService: Multi-tenant report generation, storage, hash integrity, and safe downloads.
"""

from app.reports.pdf_theme import PDFTheme
from app.reports.canvas_helpers import NumberedCanvas
from app.reports.data_collector import SecurityDataCollector
from app.reports.pdf_generator import PDFReportGenerator
from app.reports.report_service import ReportService

__all__ = [
    "PDFTheme",
    "NumberedCanvas",
    "SecurityDataCollector",
    "PDFReportGenerator",
    "ReportService",
]
