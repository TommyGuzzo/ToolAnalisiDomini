from typing import Any, Dict, List

import shodan

from ..core.config import AppConfig
from ..core.logger import get_logger

logger = get_logger("shodan_client")


def query_shodan(config: AppConfig, domain: str) -> Dict[str, Any]:
    if not config.api.shodan_api_key:
        logger.info("Shodan API key not configured")
        return {
            "enabled": False,
            "error": "SHODAN_API_KEY not set",
            "open_ports": [],
            "services": [],
            "vulnerabilities": [],
        }

    api = shodan.Shodan(config.api.shodan_api_key)
    open_ports: List[int] = []
    services: List[Dict[str, Any]] = []
    vulnerabilities: List[str] = []
    try:
        query = f"hostname:{domain}"
        res = api.search(query)
        for m in res.get("matches", []):
            port = m.get("port")
            if port is not None and port not in open_ports:
                open_ports.append(port)
            services.append(
                {
                    "ip_str": m.get("ip_str"),
                    "port": port,
                    "transport": m.get("transport"),
                    "product": m.get("product"),
                    "version": m.get("version"),
                    "tags": m.get("tags"),
                }
            )
            vulns = m.get("vulns") or {}
            for v in vulns.keys():
                if v not in vulnerabilities:
                    vulnerabilities.append(v)
        return {
            "enabled": True,
            "error": None,
            "open_ports": sorted(open_ports),
            "services": services,
            "vulnerabilities": vulnerabilities,
            "total_results": res.get("total"),
        }
    except Exception as exc:
        logger.warning(
            "Shodan query failed",
            extra={"domain": domain, "error": str(exc)},
        )
        return {
            "enabled": True,
            "error": str(exc),
            "open_ports": [],
            "services": [],
            "vulnerabilities": [],
        }
