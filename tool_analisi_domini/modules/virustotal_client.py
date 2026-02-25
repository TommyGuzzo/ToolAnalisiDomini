from typing import Any, Dict, Optional

from ..core.config import AppConfig
from ..core.http_client import HttpClient
from ..core.logger import get_logger

logger = get_logger("virustotal_client")


def _vt_get(
    http: HttpClient, api_key: str, path: str
) -> Optional[Dict[str, Any]]:
    url = f"https://www.virustotal.com/api/v3/{path.lstrip('/')}"
    headers = {"x-apikey": api_key}
    try:
        resp = http.request("GET", url, headers=headers)
        if resp.status_code == 200:
            return resp.json()
        logger.warning(
            "VirusTotal request non-200",
            extra={"url": url, "status_code": resp.status_code},
        )
        return None
    except Exception as exc:
        logger.warning(
            "VirusTotal request failed",
            extra={"url": url, "error": str(exc)},
        )
        return None


def analyze_virustotal(config: AppConfig, http: HttpClient, domain: str) -> Dict[str, Any]:
    if not config.api.virustotal_api_key:
        logger.info("VT API key not configured")
        return {
            "enabled": False,
            "error": "VT_API_KEY not set",
            "last_analysis_stats": {},
        }

    data = _vt_get(http, config.api.virustotal_api_key, f"domains/{domain}")
    if not data:
        return {
            "enabled": True,
            "error": "no data",
            "last_analysis_stats": {},
        }
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "enabled": True,
        "error": None,
        "last_analysis_stats": stats,
        "categories": attrs.get("categories", {}),
        "reputation": attrs.get("reputation"),
        "last_analysis_results": list(
            {
                "engine_name": v.get("engine_name"),
                "category": v.get("category"),
                "result": v.get("result"),
            }
            for v in (attrs.get("last_analysis_results") or {}).values()
        )[:50],
    }