from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from ..core.http_client import HttpClient
from ..core.logger import get_logger

logger = get_logger("bonus_checks")


def _fetch(http: HttpClient, url: str, allow_redirects: bool = True):
    return http.request("GET", url, allow_redirects=allow_redirects)


def _check_https_enforcement(http: HttpClient, domain: str) -> bool:
    try:
        resp = _fetch(http, f"http://{domain}", allow_redirects=True)
        final_url = resp.url
        return final_url.startswith("https://")
    except Exception as exc:
        logger.warning(
            "HTTPS enforcement check failed",
            extra={"domain": domain, "error": str(exc)},
        )
        return False


def _get_main_https_response(http: HttpClient, domain: str):
    try:
        return _fetch(http, f"https://{domain}", allow_redirects=True)
    except Exception as exc:
        logger.warning(
            "HTTPS main response fetch failed",
            extra={"domain": domain, "error": str(exc)},
        )
        return None


def _check_sri_coverage(html: str) -> float:
    soup = BeautifulSoup(html, "html.parser")
    elements: List = []
    with_integrity = 0
    for tag in soup.find_all(["script", "link"]):
        src = tag.get("src") or tag.get("href")
        if not src:
            continue
        parsed = urlparse(src)
        if not parsed.scheme and not parsed.netloc:
            continue
        elements.append(tag)
        if tag.get("integrity"):
            with_integrity += 1
    if not elements:
        return 0.0
    return with_integrity / len(elements)


def analyze_bonus_checks(http: HttpClient, domain: str) -> Dict[str, Any]:
    https_resp = _get_main_https_response(http, domain)
    headers = dict(https_resp.headers) if https_resp is not None else {}
    body = https_resp.text if https_resp is not None else ""
    https_enforced = _check_https_enforcement(http, domain)

    hsts = "strict-transport-security" in {k.lower() for k in headers.keys()}
    csp = "content-security-policy" in {k.lower() for k in headers.keys()}
    xfo = "x-frame-options" in {k.lower() for k in headers.keys()}
    sri_cov = _check_sri_coverage(body) if body else 0.0

    return {
        "https_enforced": https_enforced,
        "hsts": hsts,
        "csp": csp,
        "x_frame_options": xfo,
        "sri_coverage": sri_cov,
        "headers_sample": {k: headers[k] for k in list(headers.keys())[:20]},
    }