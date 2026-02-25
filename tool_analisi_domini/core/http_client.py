import time
from typing import Any, Dict, Optional

import requests

from .config import HttpConfig
from .logger import get_logger

logger = get_logger("http_client")


class HttpClient:
    def __init__(self, config: HttpConfig, user_agent: str) -> None:
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        json: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
    ) -> requests.Response:
        attempt = 0
        last_exc: Optional[Exception] = None
        while attempt < self.config.max_retries:
            try:
                resp = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    data=data,
                    json=json,
                    headers=headers,
                    timeout=self.config.timeout,
                    allow_redirects=allow_redirects,
                )
                return resp
            except (requests.ConnectionError, requests.Timeout) as exc:
                last_exc = exc
                attempt += 1
                sleep_for = self.config.backoff_factor * attempt
                logger.warning(
                    "HTTP request failed, retrying",
                    extra={
                        "url": url,
                        "method": method,
                        "attempt": attempt,
                        "error": str(exc),
                    },
                )
                time.sleep(sleep_for)
        assert last_exc is not None
        raise last_exc