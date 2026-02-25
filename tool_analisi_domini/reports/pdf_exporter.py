from pathlib import Path
from typing import Any, Dict, List

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


SECTION_LABELS: Dict[str, str] = {
    "CERTIFICATES_TLS": "Certificati e TLS",
    "DNS_SECURITY": "Sicurezza DNS",
    "TECH_DETECTION": "Tecnologie rilevate",
    "SHODAN": "Analisi Shodan",
    "VIRUSTOTAL": "Analisi VirusTotal",
    "BONUS_CHECKS": "Controlli aggiuntivi",
}

KEY_LABELS: Dict[str, str] = {
    # certificati / TLS
    "https_reachable": "HTTPS raggiungibile",
    "tls_version": "Versione TLS",
    "cipher": "Cifrario TLS",
    "certificate_subject": "Soggetto certificato",
    "certificate_issuer": "Autorità di certificazione",
    "certificate_not_before": "Certificato valido da",
    "certificate_not_after": "Certificato valido fino a",
    "certificate_valid": "Certificato attualmente valido",
    "certificate_expires_in_days": "Giorni alla scadenza certificato",
    "has_chain_ok": "Catena di certificazione valida",
    "crtsh_entries": "Certificati trovati su crt.sh",
    "crtsh_error": "Errore interrogazione crt.sh",
    # DNS / e‑mail security
    "spf_records": "Record SPF trovati",
    "spf_valid": "Configurazione SPF valida",
    "dmarc_records": "Record DMARC trovati",
    "dmarc_valid": "Configurazione DMARC valida",
    "dkim_selectors_checked": "Selector DKIM verificati",
    "dkim_found": "Record DKIM trovato",
}


def _prettify_key(key: str) -> str:
    """Converte una chiave tecnica in un'etichetta più leggibile."""
    if key in KEY_LABELS:
        return KEY_LABELS[key]

    text = key.replace("_", " ").strip()
    if not text:
        return key

    replacements = {
        "spf": "SPF",
        "dmarc": "DMARC",
        "dkim": "DKIM",
        "tls": "TLS",
        "ip": "IP",
        "url": "URL",
    }

    words = []
    for raw in text.split():
        lower = raw.lower()
        if lower in replacements:
            words.append(replacements[lower])
        else:
            words.append(raw.capitalize())
    return " ".join(words)


def _format_value(key: str, value: Any) -> str:
    """Formatta i valori per il PDF (booleani, liste, ecc.)."""
    if isinstance(value, bool):
        return "Sì" if value else "No"
    if value is None:
        return "-"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value

    # liste
    if isinstance(value, list):
        if key in {"spf_records", "dmarc_records"}:
            if not value:
                return "Nessun record"
            return "\n".join(f"- {item}" for item in value)
        if key == "dkim_selectors_checked":
            return ", ".join(str(item) for item in value)
        if key == "crtsh_entries":
            return f"{len(value)} certificati trovati"
        if len(value) <= 5 and all(
            isinstance(item, (str, int, float, bool)) for item in value
        ):
            return ", ".join(str(item) for item in value)
        return f"{len(value)} elementi"

    # dizionari e strutture complesse
    if isinstance(value, dict):
        return f"{len(value)} campi"

    return str(value)


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

    elements.append(Paragraph("Report analisi sicurezza dominio", title_style))
    elements.append(Spacer(1, 12))
    elements.append(
        Paragraph(
            f"Dominio analizzato: <b>{report.target}</b><br/>"
            f"Data analisi (UTC): {report.timestamp_utc}<br/>"
            f"Punteggio complessivo: {report.total_score:.1f} / {report.max_total_score:.1f} "
            f"({report.total_score_percent:.1f}%)",
            normal_style,
        )
    )
    elements.append(Spacer(1, 12))

    for section in report.sections:
        section_title = SECTION_LABELS.get(section.name, _prettify_key(section.name))
        elements.append(Paragraph(section_title, heading_style))
        elements.append(
            Paragraph(
                f"Punteggio: <b>{section.score:.1f} / {section.max_score:.1f}</b> "
                f"({round(100 * section.score / section.max_score, 1)}%) - "
                f"Stato: <b>{section.status}</b>",
                normal_style,
            )
        )
        elements.append(Spacer(1, 4))

        data = [["Campo", "Valore"]]
        for k, v in sorted(section.details.items()):
            label = _prettify_key(k)
            formatted_value = _format_value(k, v)
            data.append([label, formatted_value])
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
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
                ]
            )
        )
        elements.append(table)
        elements.append(Spacer(1, 12))

    doc.build(elements)