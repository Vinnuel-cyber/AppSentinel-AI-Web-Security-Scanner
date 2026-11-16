"""AppSentinel Canvas Helpers for PDF Generation (V9).

Implements a two-pass NumberedCanvas to dynamically compute the total page count
and render consistent running headers, footers, page numbers ("Page X of Y"),
and confidentiality notices.
"""

from reportlab.pdfgen import canvas
from reportlab.lib import colors


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas calculating total page count for dynamic 'Page X of Y' numbering."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        """Buffer page states instead of writing immediately to disk."""
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        """Second pass: draw running headers/footers with total page count and save."""
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, total_pages: int):
        """Render running header, footer, page number, and confidentiality statement."""
        # Suppress headers and footers on the cover page (Page 1)
        if self._pageNumber == 1:
            return

        self.saveState()

        # Running Header
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        self.drawString(54, 752, "AppSentinel Security Assessment Report")
        self.drawRightString(558, 752, "CONFIDENTIAL")

        # Top divider rule
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.6)
        self.line(54, 745, 558, 745)

        # Running Footer
        # Bottom divider rule
        self.line(54, 46, 558, 46)

        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        self.drawString(54, 34, "CONFIDENTIAL - Strictly for Authorized Assessment Stakeholders")
        page_str = f"Page {self._pageNumber} of {total_pages}"
        self.drawRightString(558, 34, page_str)

        self.restoreState()
