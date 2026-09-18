"""Shared HTTP layer: retry, backoff, throttling, and redaction.

Both API clients inherit from :class:`BaseApiClient`. Containment happens under
time pressure and both Graph and MDE throttle aggressively, so transport-level
resilience is not optional -- a 429 that is silently swallowed reads to the
responder as "containment succeeded" when it did not.
"""

from __future__ import annotations

import logging
import random
import time
from typing import Any, Dict, Optional

import requests

from .auth import TokenProvider

LOG = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30
MAX_ATTEMPTS = 5
RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class ApiError(RuntimeError):
    """An API call failed in a way the caller must handle."""

    def __init__(self, message: str, status_code: Optional[int] = None, body: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class BaseApiClient:
    def __init__(
        self,
        token_provider: TokenProvider,
        resource: str,
        base_url: str,
        timeout: int = DEFAULT_TIMEOUT,
        user_agent: str = "dair-containment-loop/1.0 (+https://github.com/IROC-Security)",
    ) -> None:
        self._tokens = token_provider
        self._resource = resource
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": user_agent, "Accept": "application/json"})

    # -- internals ---------------------------------------------------------

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self._tokens.get_token(self._resource)}"}

    @staticmethod
    def _backoff(attempt: int, retry_after: Optional[str]) -> float:
        if retry_after:
            try:
                return min(float(retry_after), 60.0)
            except (TypeError, ValueError):
                pass
        # Exponential with full jitter, capped.
        return min((2 ** attempt) + random.random(), 30.0)

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict] = None,
        params: Optional[Dict] = None,
        expected: tuple = (200, 201, 202, 204),
    ) -> Any:
        url = path if path.startswith("http") else f"{self._base_url}/{path.lstrip('/')}"
        last_error: Optional[str] = None

        for attempt in range(MAX_ATTEMPTS):
            try:
                response = self._session.request(
                    method,
                    url,
                    headers=self._headers(),
                    json=json_body,
                    params=params,
                    timeout=self._timeout,
                )
            except requests.RequestException as exc:
                last_error = f"transport error: {exc.__class__.__name__}"
                if attempt == MAX_ATTEMPTS - 1:
                    raise ApiError(f"{method} {url} failed after {MAX_ATTEMPTS} attempts: {last_error}")
                delay = self._backoff(attempt, None)
                LOG.warning("%s %s -- %s; retrying in %.1fs", method, url, last_error, delay)
                time.sleep(delay)
                continue

            if response.status_code in expected:
                if response.status_code == 204 or not response.content:
                    return None
                try:
                    return response.json()
                except ValueError:
                    return response.text

            if response.status_code in RETRYABLE_STATUS and attempt < MAX_ATTEMPTS - 1:
                delay = self._backoff(attempt, response.headers.get("Retry-After"))
                LOG.warning(
                    "%s %s -> HTTP %s; retrying in %.1fs (attempt %d/%d)",
                    method, url, response.status_code, delay, attempt + 1, MAX_ATTEMPTS,
                )
                time.sleep(delay)
                continue

            raise ApiError(
                f"{method} {url} -> HTTP {response.status_code}: {response.text[:800]}",
                status_code=response.status_code,
                body=response.text,
            )

        raise ApiError(f"{method} {url} exhausted retries: {last_error}")

    # -- verbs -------------------------------------------------------------

    def get(self, path: str, **kwargs) -> Any:
        return self._request("GET", path, **kwargs)

    def post(self, path: str, **kwargs) -> Any:
        return self._request("POST", path, **kwargs)

    def patch(self, path: str, **kwargs) -> Any:
        return self._request("PATCH", path, **kwargs)
