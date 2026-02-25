from typing import Any, Dict, List, Optional

from bs4 import BeautifulSoup

from ..core.http_client import HttpClient
from ..core.logger import get_logger

logger = get_logger("tech_detection")


def _fetch_page(http: HttpClient, url: str) -> Optional[Dict[str, Any]]:
    try:
        resp = http.request("GET", url)
        return {
            "url": url,
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:500_000],  # limite di sicurezza
        }
    except Exception as exc:
        logger.warning(
            "Page fetch failed",
            extra={"url": url, "error": str(exc)},
        )
        return None


def _fingerprint_technologies(headers: Dict[str, str], body: str) -> List[str]:
    techs: List[str] = []
    server = headers.get("Server", "")
    x_powered_by = headers.get("X-Powered-By", "")
    if server:
        techs.append(f"Server: {server}")
    if x_powered_by:
        techs.append(f"X-Powered-By: {x_powered_by}")

    lower_body = body.lower()
    if "wp-content" in lower_body or "wordpress" in lower_body:
        techs.append("CMS: WordPress")
    if "joomla!" in lower_body:
        techs.append("CMS: Joomla")
    if "drupal.settings" in lower_body:
        techs.append("CMS: Drupal")
    if "content=\"php" in lower_body or "x-powered-by: php" in lower_body:
        techs.append("Language: PHP")
    if "asp.net" in lower_body:
        techs.append("Framework: ASP.NET")

    soup = BeautifulSoup(body, "html.parser")
    for script in soup.find_all("script", src=True):
        src = script["src"]
        if "jquery" in src.lower():
            techs.append("Library: jQuery")
            break

    return sorted(set(techs))


def detect_technologies(http: HttpClient, domain: str) -> Dict[str, Any]:
    urls = [f"https://{domain}", f"http://{domain}"]
    pages = []
    for url in urls:
        page = _fetch_page(http, url)
        if page:
            pages.append(page)

    all_headers: Dict[str, str] = {}
    body_sample = ""
    technologies: List[str] = []
    for p in pages:
        all_headers.update(p["headers"])
        body_sample = p["body"] or body_sample
        technologies.extend(_fingerprint_technologies(p["headers"], p["body"]))

    technologies = sorted(set(technologies))
    return {
        "pages_checked": [p["url"] for p in pages],
        "technologies": technologies,
        "headers_sample": all_headers,
        "body_sample_present": bool(body_sample),
    }
