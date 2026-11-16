"""AppSentinel PDF Theme & Typography Configuration (V9).

Defines enterprise color palettes, typography hierarchies, paragraph styles,
and table formatting rules for ReportLab document generation.
"""

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY


class PDFTheme:
    """Enterprise styling constants and ReportLab stylesheet provider."""

    # Brand & Structural Colors
    PRIMARY = colors.HexColor("#0A192F")       # Deep Navy
    SECONDARY = colors.HexColor("#1E293B")     # Dark Slate
    ACCENT_CYAN = colors.HexColor("#0284C7")   # Deep Cyan / Info
    ACCENT_BLUE = colors.HexColor("#3B82F6")   # Blue Accent
    BG_LIGHT = colors.HexColor("#F8FAFC")      # Off-white table / card background
    BG_DARK = colors.HexColor("#0F172A")       # Dark SOC Cover Background
    BORDER_LIGHT = colors.HexColor("#E2E8F0")  # Subtle divider / border
    BORDER_DARK = colors.HexColor("#334155")   # Dark card border
    TEXT_DARK = colors.HexColor("#0F172A")     # Body text (dark mode print readable)
    TEXT_MUTED = colors.HexColor("#64748B")    # Secondary muted text
    TEXT_LIGHT = colors.HexColor("#FFFFFF")    # Inverted cover text

    # Severity Rating Colors
    CRITICAL = colors.HexColor("#DC2626")      # Critical (Red)
    HIGH = colors.HexColor("#EA580C")          # High (Orange)
    MEDIUM = colors.HexColor("#D97706")        # Medium (Amber)
    LOW = colors.HexColor("#2563EB")           # Low (Blue)
    INFO = colors.HexColor("#0D9488")          # Informational (Teal)

    @classmethod
    def get_severity_color(cls, severity: str) -> colors.HexColor:
        """Map vulnerability severity to its corresponding theme color."""
        s = (severity or "").upper().strip()
        if s == "CRITICAL":
            return cls.CRITICAL
        elif s == "HIGH":
            return cls.HIGH
        elif s == "MEDIUM":
            return cls.MEDIUM
        elif s == "LOW":
            return cls.LOW
        return cls.INFO

    @classmethod
    def get_stylesheet(cls):
        """Construct a comprehensive ReportLab style sheet for security reports."""
        styles = getSampleStyleSheet()

        # Cover Title
        styles.add(ParagraphStyle(
            "CoverTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=28,
            leading=34,
            textColor=cls.TEXT_LIGHT,
            alignment=TA_LEFT,
        ))

        # Cover Subtitle
        styles.add(ParagraphStyle(
            "CoverSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#94A3B8"),
            alignment=TA_LEFT,
        ))

        # Cover Meta Value
        styles.add(ParagraphStyle(
            "CoverMetaLabel",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#38BDF8"),
        ))
        styles.add(ParagraphStyle(
            "CoverMetaValue",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=cls.TEXT_LIGHT,
        ))

        # Section Headings (H1)
        styles.add(ParagraphStyle(
            "ReportH1",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=cls.PRIMARY,
            spaceBefore=14,
            spaceAfter=6,
            keepWithNext=True,
        ))

        # Subsection Headings (H2)
        styles.add(ParagraphStyle(
            "ReportH2",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=cls.SECONDARY,
            spaceBefore=10,
            spaceAfter=4,
            keepWithNext=True,
        ))

        # H3
        styles.add(ParagraphStyle(
            "ReportH3",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=14,
            textColor=cls.ACCENT_CYAN,
            spaceBefore=6,
            spaceAfter=2,
            keepWithNext=True,
        ))

        # Body Text
        styles.add(ParagraphStyle(
            "ReportBody",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=14,
            textColor=cls.TEXT_DARK,
            alignment=TA_LEFT,
            spaceAfter=6,
        ))

        # Body Justified
        styles.add(ParagraphStyle(
            "ReportBodyJustify",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=14,
            textColor=cls.TEXT_DARK,
            alignment=TA_JUSTIFY,
            spaceAfter=6,
        ))

        # Code Block
        styles.add(ParagraphStyle(
            "ReportCode",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#0F172A"),
            backColor=colors.HexColor("#F1F5F9"),
            borderPadding=5,
            spaceBefore=4,
            spaceAfter=6,
        ))

        # Callout Text
        styles.add(ParagraphStyle(
            "ReportCallout",
            parent=styles["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=9,
            leading=13,
            textColor=cls.TEXT_MUTED,
            spaceBefore=4,
            spaceAfter=6,
        ))

        # Table Cell Standard
        styles.add(ParagraphStyle(
            "TableCell",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=cls.TEXT_DARK,
        ))

        # Table Cell Bold
        styles.add(ParagraphStyle(
            "TableCellBold",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=12,
            textColor=cls.TEXT_DARK,
        ))

        # Table Cell Header
        styles.add(ParagraphStyle(
            "TableCellHeader",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=cls.TEXT_LIGHT,
            alignment=TA_LEFT,
        ))

        # Table Cell Centered
        styles.add(ParagraphStyle(
            "TableCellCenter",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=cls.TEXT_DARK,
            alignment=TA_CENTER,
        ))

        return styles
