import argparse
import datetime
from pathlib import Path

from tool_analisi_domini.core.config import load_config
from tool_analisi_domini.core.http_client import HttpClient
from tool_analisi_domini.core.logger import get_logger
from tool_analisi_domini.core.models import ScanReport
from tool_analisi_domini.core import scoring
from tool_analisi_domini.modules.certificates_tls import (
    analyze_certificates_and_tls,
)
from tool_analisi_domini.modules.dns_security import analyze_dns_security
from tool_analisi_domini.modules.tech_detection import detect_technologies
from tool_analisi_domini.modules.shodan_client import query_shodan
from tool_analisi_domini.modules.virustotal_client import analyze_virustotal
from tool_analisi_domini.modules.bonus_checks import analyze_bonus_checks
from tool_analisi_domini.reports.json_exporter import export_json
from tool_analisi_domini.reports.pdf_exporter import export_pdf

logger = get_logger("main")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Tool interno per analisi di sicurezza domini"
    )
    parser.add_argument(
        "--domain",
        required=True,
        help="Dominio target (es. example.com)",
    )
    parser.add_argument(
        "--output-dir",
        default="output",
        help="Directory per output JSON/PDF",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    domain = args.domain.strip()
    output_dir = Path(args.output_dir)

    config = load_config()
    http_client = HttpClient(config.http, config.user_agent)

    logger.info("Starting domain scan", extra={"domain": domain})

    ts = datetime.datetime.now(datetime.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    cert_tls_data = analyze_certificates_and_tls(http_client, domain)
    dns_data = analyze_dns_security(domain)
    tech_data = detect_technologies(http_client, domain)
    shodan_data = query_shodan(config, domain)
    vt_data = analyze_virustotal(config, http_client, domain)
    bonus_data = analyze_bonus_checks(http_client, domain)

    s_cert = scoring.score_certificates_tls(cert_tls_data)
    s_dns = scoring.score_dns_security(dns_data)
    s_tech = scoring.score_tech_detection(tech_data)
    s_shodan = scoring.score_shodan(shodan_data)
    s_vt = scoring.score_virustotal(vt_data)
    s_bonus = scoring.score_bonus(bonus_data)

    sections = [s_cert, s_dns, s_tech, s_shodan, s_vt, s_bonus]
    report = ScanReport(target=domain, timestamp_utc=ts, sections=sections)

    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{domain}_report.json"
    pdf_path = output_dir / f"{domain}_report.pdf"

    export_json(report, json_path)
    export_pdf(report, pdf_path)

    logger.info(
        "Scan completed",
        extra={
            "domain": domain,
            "json_report": str(json_path),
            "pdf_report": str(pdf_path),
            "total_score": report.total_score,
            "max_total_score": report.max_total_score,
            "total_score_percent": report.total_score_percent,
        },
    )


if __name__ == "__main__":
    main()