import os
from dataclasses import dataclass
from typing import Optional

try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    # Se python-dotenv non è installato non è bloccante
    pass


@dataclass
class ApiConfig:
    shodan_api_key: Optional[str]
    virustotal_api_key: Optional[str]


@dataclass
class HttpConfig:
    timeout: float = 10.0
    max_retries: int = 3
    backoff_factor: float = 0.5


@dataclass
class AppConfig:
    api: ApiConfig
    http: HttpConfig
    user_agent: str = "Internal-Security-Domain-Analyzer/1.0"


def load_config() -> AppConfig:
    api_cfg = ApiConfig(
        shodan_api_key=os.getenv("SHODAN_API_KEY"),
        virustotal_api_key=os.getenv("VT_API_KEY"),
    )
    http_cfg = HttpConfig(
        timeout=float(os.getenv("HTTP_TIMEOUT", "10.0")),
        max_retries=int(os.getenv("HTTP_MAX_RETRIES", "3")),
        backoff_factor=float(os.getenv("HTTP_BACKOFF_FACTOR", "0.5")),
    )
    return AppConfig(api=api_cfg, http=http_cfg)