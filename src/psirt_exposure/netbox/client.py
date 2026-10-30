"""Minimal NetBox REST API client (httpx). The API token is never logged or printed."""

from __future__ import annotations

import os
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from psirt_exposure.psirt.openvuln import read_env_file

URL_ENV = "NETBOX_URL"
TOKEN_ENV = "NETBOX_TOKEN"
DEFAULT_TIMEOUT = 30.0
PAGE_SIZE = 200
# Upper bound on followed `next` links (200 * 1000 objects), against pagination loops.
MAX_PAGES = 1000

Params = Mapping[str, str | Sequence[str]]


class NetBoxError(RuntimeError):
    """The NetBox API failed or returned something unexpected."""


def auth_header(token: str) -> str:
    """v2 tokens (``nbt_<key>.<secret>``, NetBox 4.5+) use ``Bearer``; v1 tokens ``Token``."""
    return f"Bearer {token}" if token.startswith("nbt_") else f"Token {token}"


class NetBoxClient:
    def __init__(
        self,
        url: str,
        token: str,
        *,
        http: httpx.Client | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.url = url.rstrip("/")
        self._token = token
        self._http = http or httpx.Client(timeout=timeout)

    def __repr__(self) -> str:
        return f"NetBoxClient(url={self.url!r})"

    def _request(self, method: str, url: str, **kw: Any) -> Any:
        headers = {"Authorization": auth_header(self._token), "Accept": "application/json"}
        try:
            response = self._http.request(method, url, headers=headers, **kw)
        except httpx.HTTPError as exc:
            raise NetBoxError(f"cannot reach NetBox at {self.url}: {type(exc).__name__}") from None
        if response.status_code in (401, 403):
            raise NetBoxError(f"NetBox rejected the API token (HTTP {response.status_code})")
        if response.status_code >= 400:
            detail = response.text[:300].replace("\n", " ")
            raise NetBoxError(f"NetBox {method} {url} failed: HTTP {response.status_code} {detail}")
        if response.status_code == 204:
            return None
        try:
            return response.json()
        except ValueError:
            raise NetBoxError(f"NetBox {method} {url} returned non-JSON") from None

    def _url(self, path: str) -> str:
        return f"{self.url}/api/{path.strip('/')}/"

    def list(self, path: str, params: Params | None = None) -> Iterator[dict[str, Any]]:
        """All objects of a list endpoint, following ``next`` links."""
        url: str | None = self._url(path)
        query: dict[str, Any] | None = {"limit": str(PAGE_SIZE), **(params or {})}
        for _ in range(MAX_PAGES):
            if not url:
                return
            body = self._request("GET", url, params=query)
            if not isinstance(body, dict) or not isinstance(body.get("results"), list):
                raise NetBoxError(f"unexpected list response from {path}")
            yield from body["results"]
            nxt = body.get("next")
            url, query = (self._same_origin(nxt) if nxt else None), None  # `next` has the query
        raise NetBoxError(f"more than {MAX_PAGES} pages from {path}; stopping")

    def _same_origin(self, link: object) -> str:
        """Pin a pagination link to the configured scheme and host.

        The token must only go to ``self.url``. NetBox behind a proxy often returns ``http://``
        links for an ``https://`` site; using the configured origin avoids a cleartext downgrade,
        and a link to another host or outside ``/api/`` is refused.
        """
        base = urlsplit(self.url)
        parts = urlsplit(str(link))
        api = base.path.rstrip("/") + "/api/"
        if (parts.hostname or base.hostname) != base.hostname or not parts.path.startswith(api):
            raise NetBoxError("NetBox returned a pagination link outside the configured API")
        return urlunsplit((base.scheme, base.netloc, parts.path, parts.query, ""))

    def create(self, path: str, data: Mapping[str, Any]) -> dict[str, Any]:
        body = self._request("POST", self._url(path), json=data)
        if not isinstance(body, dict):
            raise NetBoxError(f"unexpected create response from {path}")
        return body

    def update(self, path: str, obj_id: int, data: Mapping[str, Any]) -> dict[str, Any]:
        body = self._request("PATCH", f"{self._url(path)}{obj_id}/", json=data)
        if not isinstance(body, dict):
            raise NetBoxError(f"unexpected update response from {path}")
        return body


def netbox_from_env(env_file: Path | None = Path(".env")) -> NetBoxClient | None:
    """A client from ``NETBOX_URL`` / ``NETBOX_TOKEN`` (environment first, then ``env_file``)."""
    file_values = read_env_file(env_file) if env_file else {}
    url = os.environ.get(URL_ENV) or file_values.get(URL_ENV)
    token = os.environ.get(TOKEN_ENV) or file_values.get(TOKEN_ENV)
    if not url or not token:
        return None
    return NetBoxClient(url, token)
