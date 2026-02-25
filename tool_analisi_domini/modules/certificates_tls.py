import datetime
import socket
import ssl
from typing import Any, Dict, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from ..core.http_client import HttpClient
from ..core.logger import get_logger

logger = get_logger("certificates_tls")


def _get_tls_info(domain: str, port: int = 443) -> Dict[str, Any]:
    context = ssl.create_default_context()
    data: Dict[str, Any] = {
        "https_reachable": False,
        "tls_version": None,
        "cipher": None,
        "certificate_subject": None,
        "certificate_issuer": None,
        "certificate_not_before": None,
        "certificate_not_after": None,
        "certificate_valid": False,
        "certificate_expires_in_days": None,
        "has_chain_ok": False,
    }
    try:
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                data["https_reachable"] = True
                cipher = ssock.cipher()
                data["cipher"] = cipher[0] if cipher else None
                data["tls_version"] = ssock.version()
                der_cert = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                data["certificate_subject"] = cert.subject.rfc4514_string()
                data["certificate_issuer"] = cert.issuer.rfc4514_string()
                not_before = cert.not_valid_before_utc
                not_after = cert.not_valid_after_utc
                data["certificate_not_before"] = not_before.isoformat()
                data["certificate_not_after"] = not_after.isoformat()
                now = datetime.datetime.now(datetime.UTC)
                data["certificate_valid"] = not_before <= now <= not_after
                delta = not_after - now
                data["certificate_expires_in_days"] = max(delta.days, 0)
                data["has_chain_ok"] = True
    except Exception as exc:
        logger.warning(
            "TLS analysis failed",
            extra={"domain": domain, "error": str(exc)},
        )
    return data


def _query_crtsh(http: HttpClient, domain: str) -> Dict[str, Any]:
    url = "https://crt.sh/"
    params = {"q": domain, "output": "json"}
    try:
        resp = http.request("GET", url, params=params)
        if resp.status_code != 200:
            return {"crtsh_entries": [], "crtsh_error": f"status {resp.status_code}"}
        try:
            entries = resp.json()
        except ValueError:
            return {"crtsh_entries": [], "crtsh_error": "invalid json"}
        # riduci info per non generare report enormi
        simplified = [
            {
                "issuer_ca_id": e.get("issuer_ca_id"),
                "issuer_name": e.get("issuer_name"),
                "name_value": e.get("name_value"),
                "not_before": e.get("not_before"),
                "not_after": e.get("not_after"),
            }
            for e in entries[:50]
        ]
        return {"crtsh_entries": simplified, "crtsh_error": None}
    except Exception as exc:
        logger.warning(
            "crt.sh query failed",
            extra={"domain": domain, "error": str(exc)},
        )
        return {"crtsh_entries": [], "crtsh_error": str(exc)}


def analyze_certificates_and_tls(http: HttpClient, domain: str) -> Dict[str, Any]:
    tls_info = _get_tls_info(domain)
    crtsh_info = _query_crtsh(http, domain)
    merged: Dict[str, Any] = {}
    merged.update(tls_info)
    merged.update(crtsh_info)
    return merged