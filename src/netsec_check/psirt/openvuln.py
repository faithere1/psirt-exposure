"""Cisco PSIRT openVuln API v2 client (OAuth2 client credentials).

Credentials come from the environment (``CISCO_CLIENT_ID`` / ``CISCO_CLIENT_SECRET``), optionally
loaded from a ``.env`` file. The secret and the access token are never logged, printed or put in
exception messages.
"""

from __future__ import annotations

import contextlib
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

DEFAULT_TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
DEFAULT_API_URL = "https://apix.cisco.com/security/advisories/v2"
DEFAULT_TIMEOUT = 30.0
CLIENT_ID_ENV = "CISCO_CLIENT_ID"
CLIENT_SECRET_ENV = "CISCO_CLIENT_SECRET"
# Renew the token this many seconds before it expires.
TOKEN_MARGIN = 60.0


class OpenVulnError(RuntimeError):
    """The token endpoint or the openVuln API failed."""


def read_env_file(path: Path) -> dict[str, str]:
    """``KEY=VALUE`` lines of a dotenv file (no interpolation; quotes are stripped)."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.removeprefix("export ").split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def credentials_from_env(env_file: Path | None = Path(".env")) -> tuple[str, str] | None:
    """Client id and secret from the environment, falling back to ``env_file``."""
    file_values = read_env_file(env_file) if env_file else {}
    client_id = os.environ.get(CLIENT_ID_ENV) or file_values.get(CLIENT_ID_ENV)
    secret = os.environ.get(CLIENT_SECRET_ENV) or file_values.get(CLIENT_SECRET_ENV)
    if not client_id or not secret:
        return None
    return client_id, secret


def _str_list(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(v) for v in value if v and str(v) != "NA")


def _opt_str(value: Any) -> str | None:
    return str(value) if value not in (None, "", "NA") else None


@dataclass(frozen=True)
class OpenVulnAdvisory:
    """The fields of an openVuln advisory record that netsec-check uses."""

    advisory_id: str
    title: str
    cves: tuple[str, ...]
    first_fixed: tuple[str, ...] = ()
    sir: str | None = None
    cvss_base_score: str | None = None
    publication_url: str | None = None
    csaf_url: str | None = None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> OpenVulnAdvisory:
        try:
            advisory_id = str(data["advisoryId"])
        except KeyError as exc:
            raise OpenVulnError("advisory record without advisoryId") from exc
        return cls(
            advisory_id=advisory_id,
            title=str(data.get("advisoryTitle", "")),
            cves=tuple(sorted(_str_list(data.get("cves")))),
            first_fixed=_str_list(data.get("firstFixed")),
            sir=_opt_str(data.get("sir")),
            cvss_base_score=_opt_str(data.get("cvssBaseScore")),
            publication_url=_opt_str(data.get("publicationUrl")),
            csaf_url=_opt_str(data.get("csafUrl")),
        )


class OpenVulnClient:
    """Small synchronous openVuln client with token caching and rate-limit retries."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        token_url: str = DEFAULT_TOKEN_URL,
        api_url: str = DEFAULT_API_URL,
        http: httpx.Client | None = None,
        max_retries: int = 3,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self.token_url = token_url
        self.api_url = api_url.rstrip("/")
        self._http = http or httpx.Client(timeout=DEFAULT_TIMEOUT)
        self.max_retries = max_retries
        self._sleep = sleep
        self._clock = clock
        self._token: str | None = None
        self._token_expires = 0.0

    def __repr__(self) -> str:
        return f"OpenVulnClient(api_url={self.api_url!r})"

    def _fetch_token(self) -> str:
        data = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        try:
            response = self._http.post(self.token_url, data=data)
        except httpx.HTTPError as exc:
            raise OpenVulnError(f"token request to {self.token_url} failed: {exc}") from None
        if response.status_code != 200:
            # The body of an OAuth error names the error code only; it holds no credentials.
            code = ""
            with contextlib.suppress(ValueError, AttributeError):
                code = str(response.json().get("error", ""))
            raise OpenVulnError(
                f"token request returned HTTP {response.status_code}"
                + (f" ({code})" if code else "")
                + f"; check {CLIENT_ID_ENV} / {CLIENT_SECRET_ENV}"
            )
        try:
            body = response.json()
            token = str(body["access_token"])
            expires_in = float(body.get("expires_in", 3600))
        except (ValueError, KeyError, TypeError):
            raise OpenVulnError("token endpoint returned an unexpected response") from None
        self._token = token
        self._token_expires = self._clock() + expires_in - TOKEN_MARGIN
        return token

    def _access_token(self) -> str:
        if self._token is None or self._clock() >= self._token_expires:
            return self._fetch_token()
        return self._token

    def get_json(self, path: str, params: dict[str, str] | None = None) -> Any:
        """GET ``api_url + path``. Returns None for openVuln's ``NO_DATA_FOUND``."""
        url = f"{self.api_url}/{path.lstrip('/')}"
        refreshed = False
        attempt = 0
        while True:
            headers = {
                "Authorization": f"Bearer {self._access_token()}",
                "Accept": "application/json",
            }
            try:
                response = self._http.get(url, params=params, headers=headers)
            except httpx.HTTPError as exc:
                raise OpenVulnError(f"request to {url} failed: {exc}") from None
            if response.status_code == 401 and not refreshed:
                self._token = None
                refreshed = True
                continue
            if response.status_code in (429, 503) and attempt < self.max_retries:
                attempt += 1
                self._sleep(_retry_after(response, attempt))
                continue
            break
        body: Any = None
        with contextlib.suppress(ValueError):
            body = response.json()
        if isinstance(body, dict) and body.get("errorCode") == "NO_DATA_FOUND":
            return None
        if response.status_code != 200:
            detail = body.get("errorMessage") if isinstance(body, dict) else None
            raise OpenVulnError(
                f"{url} returned HTTP {response.status_code}" + (f": {detail}" if detail else "")
            )
        if body is None:
            raise OpenVulnError(f"{url} returned non-JSON content")
        return body

    def advisories_for_version(
        self, version: str, os_type: str = "iosxe"
    ) -> list[OpenVulnAdvisory]:
        """Advisories that affect ``version`` of ``os_type`` (empty if none)."""
        body = self.get_json(f"OSType/{os_type}", {"version": version})
        return _advisories(body)

    def advisory(self, advisory_id: str) -> OpenVulnAdvisory | None:
        body = self.get_json(f"advisory/{advisory_id}")
        found = _advisories(body)
        return found[0] if found else None

    def csaf(self, advisory: OpenVulnAdvisory) -> dict[str, Any]:
        """The public CSAF document behind an advisory (fetched without credentials)."""
        if not advisory.csaf_url:
            raise OpenVulnError(f"{advisory.advisory_id} has no csafUrl")
        try:
            response = self._http.get(advisory.csaf_url)
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise OpenVulnError(f"cannot fetch CSAF for {advisory.advisory_id}: {exc}") from None
        if not isinstance(data, dict):
            raise OpenVulnError(f"CSAF for {advisory.advisory_id} is not a JSON object")
        return data


def _retry_after(response: httpx.Response, attempt: int) -> float:
    value = response.headers.get("Retry-After")
    if value:
        try:
            return min(float(value), 60.0)
        except ValueError:
            pass
    return float(2**attempt)


def _advisories(body: Any) -> list[OpenVulnAdvisory]:
    if body is None:
        return []
    if isinstance(body, dict) and "advisories" in body:
        records = body["advisories"]
    elif isinstance(body, dict) and "advisoryId" in body:
        records = [body]
    elif isinstance(body, list):
        records = body
    else:
        raise OpenVulnError(f"unexpected openVuln response: {str(body)[:200]}")
    if not isinstance(records, list):
        raise OpenVulnError("openVuln 'advisories' is not a list")
    return [OpenVulnAdvisory.from_api(r) for r in records if isinstance(r, dict)]
