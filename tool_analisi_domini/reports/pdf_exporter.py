rom pathlib import Path
from typing import List

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from ..core.models import ScanReport


def export_pdf(report: ScanReport, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
    )

    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    heading_style = styles["Heading2"]
    normal_style = styles["BodyText"]
    bold_style = ParagraphStyle(
        "Bold",
        parent=normal_style,
        spaceAfter=4,
        leading=12,
        fontName="Helvetica-Bold",
    )

    elements: List = []

    elements.append(Paragraph("Domain Security Analysis Report", title_style))
    elements.append(Spacer(1, 12))
    elements.append(
        Paragraph(
            f"Target: <b>{report.target}</b><br/>"
            f"Timestamp (UTC): {report.timestamp_utc}<br/>"
            f"Score totale: {report.total_score:.1f} / {report.max_total_score:.1f} "
            f"({report.total_score_percent:.1f}%)",
            normal_style,
        )
    )
    elements.append(Spacer(1, 12))

    for section in report.sections:
        elements.append(Paragraph(section.name, heading_style))
        elements.append(
            Paragraph(
                f"Punteggio: <b>{section.score:.1f} / {section.max_score:.1f}</b> "
                f"({round(100 * section.score / section.max_score, 1)}%) - "
                f"Stato: <b>{section.status}</b>",
                normal_style,
            )
        )
        elements.append(Spacer(1, 4))

        data = [["Chiave", "Valore"]]
        for k, v in sorted(section.details.items()):
            data.append([str(k), str(v)])
        table = Table(data, colWidths=[60 * mm, 90 * mm])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ]
            )
        )
        elements.append(table)
        elements.append(Spacer(1, 12))

    doc.build(elements)