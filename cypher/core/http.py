"""Shared HTTP client with a consistent user-agent and per-host rate limiting.

httpx is imported lazily so the package (and module discovery) works even when
httpx is not yet installed.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse

from .settings import Settings


class HttpClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._client: Any = None
        self._last_hit: dict[str, float] = {}

    def _client_or_create(self) -> Any:
        if self._client is None:
            import httpx  # lazy

            self._client = httpx.Client(
                follow_redirects=True,
                timeout=self.settings.timeout,
                headers={"User-Agent": self.settings.user_agent},
            )
        return self._client

    def _throttle(self, url: str) -> None:
        host = urlparse(url).netloc
        min_gap = self.settings.rate_limit_per_host
        last = self._last_hit.get(host)
        now = time.monotonic()
        if last is not None and (now - last) < min_gap:
            time.sleep(min_gap - (now - last))
        self._last_hit[host] = time.monotonic()

    def get(self, url: str, **kwargs: Any) -> Any:
        self._throttle(url)
        return self._client_or_create().get(url, **kwargs)

    def get_json(self, url: str, **kwargs: Any) -> Any:
        resp = self.get(url, **kwargs)
        resp.raise_for_status()
        return resp.json()

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
