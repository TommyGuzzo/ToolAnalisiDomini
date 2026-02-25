from typing import Any, Dict, List

import dns.resolver

from ..core.logger import get_logger

logger = get_logger("dns_security")


def _get_txt_records(name: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(name, "TXT")
        records: List[str] = []
        for r in answers:
            txt = "".join([b.decode("utf-8") for b in r.strings])
            records.append(txt)
        return records
    except Exception as exc:
        logger.warning(
            "TXT lookup failed",
            extra={"name": name, "error": str(exc)},
        )
        return []


def analyze_dns_security(domain: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "spf_records": [],
        "spf_valid": False,
        "dmarc_records": [],
        "dmarc_valid": False,
        "dkim_selectors_checked": [],
        "dkim_found": False,
    }
    spf_records = _get_txt_records(domain)
    result["spf_records"] = spf_records
    result["spf_valid"] = any(r.lower().startswith("v=spf1") for r in spf_records)

    dmarc_domain = f"_dmarc.{domain}"
    dmarc_records = _get_txt_records(dmarc_domain)
    result["dmarc_records"] = dmarc_records
    result["dmarc_valid"] = any(r.lower().startswith("v=dmarc1") for r in dmarc_records)

    selectors = ["default", "selector1", "selector2"]
    result["dkim_selectors_checked"] = selectors
    for sel in selectors:
        dkim_domain = f"{sel}._domainkey.{domain}"
        txts = _get_txt_records(dkim_domain)
        if any("v=DKIM1".lower() in r.lower() for r in txts):
            result["dkim_found"] = True
            break

    return result