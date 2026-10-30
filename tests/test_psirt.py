"""openVuln client, CSAF/openVuln version sources and the KEV catalog (offline).

HTTP is served by ``httpx.MockTransport``; tokens and secrets below are fake.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from netsec_check.psirt import (
    CsafVersionSource,
    OpenVulnClient,
    OpenVulnError,
    OpenVulnVersionSource,
    credentials_from_env,
    csaf_affected_versions,
    fetch_kev,
    load_kev,
    normalize_version,
)
from netsec_check.psirt.kev import KevError
from netsec_check.psirt.openvuln import DEFAULT_API_URL, DEFAULT_TOKEN_URL, read_env_file
from netsec_check.psirt.versions import release_train

ROOT = Path(__file__).resolve().parent.parent
PSIRT = ROOT / "tests/fixtures/psirt"
KEV_FILE = ROOT / "tests/fixtures/kev/known_exploited_vulnerabilities.json"
WEBUI = "cisco-sa-iosxe-webui-privesc-j22SaA4z"
SNMP = "cisco-sa-snmp-x4LPhte"
FAKE_ID = "fake-client-id"
FAKE_SECRET = "fake-client-secret-0000"
FAKE_TOKEN = "fake-access-token-0000"

Handler = Callable[[httpx.Request], httpx.Response]


# --- versions -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [
        ("17.09.03a", "17.9.3a"),
        ("16.03.07", "16.3.7"),
        ("17.12.02", "17.12.2"),
        ("17.10.1", "17.10.1"),
        ("3.7.0S", "3.7.0S"),
        (" 17.06.05 ", "17.6.5"),
    ],
)
def test_normalize_version(raw: str, normalized: str) -> None:
    assert normalize_version(raw) == normalized


def test_release_train() -> None:
    assert release_train("17.09.03a") == (17, 9)
    assert release_train("16.12.1s") == (16, 12)
    assert release_train("3.16.0S") is None
    assert release_train("17.11.99SW") is None


def test_csaf_versions_only_ios_xe_family() -> None:
    csaf = json.loads((PSIRT / "cisco-sa-asa-ftd-ios-dos-kPEpQGGK.json").read_text())
    versions = csaf_affected_versions(csaf)
    assert versions is not None
    assert "17.9.3a" in versions.affected
    # IOS (15.x) and ASA (9.x) releases in the same advisory are not IOS XE versions.
    assert not any(v.startswith(("15.", "9.")) for v in versions.affected)


def test_csaf_without_ios_xe_family() -> None:
    assert csaf_affected_versions({"product_tree": {}, "vulnerabilities": []}) is None


def _tiny_csaf(versions: dict[str, bool], family: str = "Cisco IOS XE Software") -> dict[str, Any]:
    leaves = [
        {"category": "product_version", "name": v, "product": {"product_id": f"P{i}", "name": v}}
        for i, v in enumerate(versions)
    ]
    affected = [f"P{i}" for i, hit in enumerate(versions.values()) if hit]
    return {
        "product_tree": {
            "branches": [
                {
                    "category": "vendor",
                    "name": "Cisco",
                    "branches": [
                        {"category": "product_family", "name": family, "branches": leaves}
                    ],
                }
            ]
        },
        "vulnerabilities": [{"product_status": {"known_affected": affected}}],
    }


def test_csaf_train_rules() -> None:
    v = csaf_affected_versions(
        _tiny_csaf({"16.12.4": True, "16.12.5": False, "17.6.1": True, "17.11.99SW": True})
    )
    assert v is not None
    assert v.trains == {(16, 12), (17, 6)}
    assert v.version_affected("16.12.04") is True
    assert v.version_affected("16.12.05") is False  # listed train, version not affected
    assert v.version_affected("17.06.02") is False  # listed train, later release
    assert v.version_affected("17.09.01") is False  # train newer than the advisory
    assert v.version_affected("16.03.07") is None  # older train never evaluated (EoL)
    assert v.version_affected("17.11.99SW") is True


def test_csaf_relationship_products_count() -> None:
    csaf = _tiny_csaf({"17.3.1": False})
    csaf["product_tree"]["relationships"] = [
        {
            "category": "installed_on",
            "product_reference": "P0",
            "relates_to_product_reference": "X1",
            "full_product_name": {"product_id": "P0:X1", "name": "17.3.1 on something"},
        }
    ]
    csaf["vulnerabilities"][0]["product_status"]["known_affected"] = ["P0:X1"]
    v = csaf_affected_versions(csaf)
    assert v is not None and "17.3.1" in v.affected


def test_csaf_version_source_on_fixtures() -> None:
    src = CsafVersionSource.from_dir(PSIRT)
    # Web UI: 17.9.3a affected, fixed in 17.9.4a.
    assert src.version_affected(WEBUI, "17.09.03a") is True
    assert src.version_affected(WEBUI, "17.09.04a") is False
    # SNMP: 16.3 is past end of maintenance and not evaluated.
    assert src.version_affected(SNMP, "16.03.07") is None
    assert src.version_affected("cisco-sa-unknown", "17.09.03a") is None


# --- openVuln client ------------------------------------------------------------------------


class FakeApi:
    """Token endpoint + OS-version endpoint with call recording."""

    def __init__(self, routes: dict[str, Handler] | None = None) -> None:
        self.calls: list[httpx.Request] = []
        self.tokens_issued = 0
        self.routes = routes or {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        url = str(request.url)
        if url == DEFAULT_TOKEN_URL:
            self.tokens_issued += 1
            return httpx.Response(
                200,
                json={
                    "access_token": f"{FAKE_TOKEN}-{self.tokens_issued}",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )
        for prefix, handler in self.routes.items():
            if url.startswith(prefix):
                return handler(request)
        return httpx.Response(404, json={"errorCode": "NOT_FOUND"})


def _client(api: FakeApi, **kw: Any) -> OpenVulnClient:
    return OpenVulnClient(
        FAKE_ID,
        FAKE_SECRET,
        http=httpx.Client(transport=httpx.MockTransport(api)),
        sleep=lambda _s: None,
        **kw,
    )


OSTYPE = f"{DEFAULT_API_URL}/OSType/iosxe"
ADVISORY_RECORD = {
    "advisoryId": WEBUI,
    "advisoryTitle": "Multiple Vulnerabilities in Cisco IOS XE Software Web UI Feature",
    "cves": ["CVE-2023-20273", "CVE-2023-20198"],
    "firstFixed": ["17.9.4a"],
    "sir": "Critical",
    "cvssBaseScore": "10.0",
    "publicationUrl": "https://sec.cloudapps.cisco.com/security/center/content/x",
    "csafUrl": "https://sec.cloudapps.cisco.com/security/center/contentjson/x.json",
}


def test_token_request_and_bearer_header() -> None:
    api = FakeApi({OSTYPE: lambda r: httpx.Response(200, json={"advisories": [ADVISORY_RECORD]})})
    client = _client(api)
    [adv] = client.advisories_for_version("17.9.3a")
    assert adv.advisory_id == WEBUI
    assert adv.cves == ("CVE-2023-20198", "CVE-2023-20273")
    assert adv.first_fixed == ("17.9.4a",)
    token_req, api_req = api.calls
    form = dict(httpx.QueryParams(token_req.content.decode()))
    assert form == {
        "grant_type": "client_credentials",
        "client_id": FAKE_ID,
        "client_secret": FAKE_SECRET,
    }
    assert api_req.headers["Authorization"] == f"Bearer {FAKE_TOKEN}-1"
    assert api_req.url.params["version"] == "17.9.3a"


def test_token_is_cached_until_expiry() -> None:
    now = [0.0]
    api = FakeApi({OSTYPE: lambda r: httpx.Response(200, json={"advisories": []})})
    client = _client(api, clock=lambda: now[0])
    client.advisories_for_version("17.9.3a")
    client.advisories_for_version("17.6.5")
    assert api.tokens_issued == 1
    now[0] = 3600.0
    client.advisories_for_version("17.6.5")
    assert api.tokens_issued == 2


def test_401_refreshes_token_once() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers["Authorization"].endswith("-1"):
            return httpx.Response(401, json={"errorCode": "UNAUTHORIZED"})
        return httpx.Response(200, json={"advisories": []})

    api = FakeApi({OSTYPE: handler})
    assert _client(api).advisories_for_version("17.9.3a") == []
    assert api.tokens_issued == 2


def test_429_is_retried_with_retry_after() -> None:
    replies = iter(
        [
            httpx.Response(429, headers={"Retry-After": "2"}),
            httpx.Response(200, json={"advisories": [ADVISORY_RECORD]}),
        ]
    )
    waits: list[float] = []
    api = FakeApi({OSTYPE: lambda r: next(replies)})
    client = OpenVulnClient(
        FAKE_ID,
        FAKE_SECRET,
        http=httpx.Client(transport=httpx.MockTransport(api)),
        sleep=waits.append,
    )
    assert len(client.advisories_for_version("17.9.3a")) == 1
    assert waits == [2.0]


def test_no_data_found_is_empty() -> None:
    api = FakeApi(
        {
            OSTYPE: lambda r: httpx.Response(
                404, json={"errorCode": "NO_DATA_FOUND", "errorMessage": "No data found"}
            )
        }
    )
    assert _client(api).advisories_for_version("17.18.1") == []


def test_api_error_raises() -> None:
    api = FakeApi({OSTYPE: lambda r: httpx.Response(400, json={"errorMessage": "Invalid version"})})
    with pytest.raises(OpenVulnError, match="Invalid version"):
        _client(api).advisories_for_version("bogus")


def test_token_failure_never_leaks_secret() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid_client"})

    client = OpenVulnClient(
        FAKE_ID, FAKE_SECRET, http=httpx.Client(transport=httpx.MockTransport(handler))
    )
    with pytest.raises(OpenVulnError) as info:
        client.advisories_for_version("17.9.3a")
    assert "invalid_client" in str(info.value)
    assert FAKE_SECRET not in str(info.value)
    assert FAKE_SECRET not in repr(client)


def test_advisory_by_id_and_csaf() -> None:
    csaf_doc = json.loads((PSIRT / f"{WEBUI}.json").read_text())
    api = FakeApi(
        {
            f"{DEFAULT_API_URL}/advisory/": lambda r: httpx.Response(200, json=ADVISORY_RECORD),
            "https://sec.cloudapps.cisco.com/": lambda r: httpx.Response(200, json=csaf_doc),
        }
    )
    client = _client(api)
    adv = client.advisory(WEBUI)
    assert adv is not None and adv.sir == "Critical"
    doc = client.csaf(adv)
    assert doc["document"]["tracking"]["id"] == WEBUI
    # The public CSAF download must not carry the bearer token.
    assert "Authorization" not in api.calls[-1].headers


def test_openvuln_version_source_caches_per_version() -> None:
    api = FakeApi({OSTYPE: lambda r: httpx.Response(200, json={"advisories": [ADVISORY_RECORD]})})
    src = OpenVulnVersionSource(_client(api))
    assert src.version_affected(WEBUI, "17.09.03a") is True
    assert src.version_affected(SNMP, "17.9.3a") is False
    assert sum(1 for c in api.calls if str(c.url).startswith(OSTYPE)) == 1


def test_openvuln_version_source_failure_is_unknown() -> None:
    warnings: list[str] = []
    api = FakeApi({OSTYPE: lambda r: httpx.Response(500)})
    src = OpenVulnVersionSource(_client(api, max_retries=0), warn=warnings.append)
    assert src.version_affected(WEBUI, "17.9.3a") is None
    assert len(warnings) == 1 and "17.9.3a" in warnings[0]


# --- credentials ----------------------------------------------------------------------------


def test_credentials_from_env_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CISCO_CLIENT_ID", raising=False)
    monkeypatch.delenv("CISCO_CLIENT_SECRET", raising=False)
    env = tmp_path / ".env"
    env.write_text(
        f"# comment\nCISCO_CLIENT_ID={FAKE_ID}\nexport CISCO_CLIENT_SECRET='{FAKE_SECRET}'\n"
    )
    assert read_env_file(env)["CISCO_CLIENT_SECRET"] == FAKE_SECRET
    assert credentials_from_env(env) == (FAKE_ID, FAKE_SECRET)
    monkeypatch.setenv("CISCO_CLIENT_ID", "from-environment")
    assert credentials_from_env(env) == ("from-environment", FAKE_SECRET)
    assert credentials_from_env(tmp_path / "missing") is None


# --- KEV ------------------------------------------------------------------------------------


def test_kev_fixture_lookup() -> None:
    kev = load_kev(KEV_FILE)
    hits = kev.lookup(["CVE-2023-20273", "CVE-2023-20198", "CVE-2023-20198"])
    assert [h.cve for h in hits] == ["CVE-2023-20198"]
    assert hits[0].date_added == "2023-10-16"
    assert kev.lookup(["CVE-2022-20919"]) == []


def test_fetch_kev_and_errors() -> None:
    data = json.loads(KEV_FILE.read_text())
    ok = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=data)))
    assert "CVE-2018-0171" in fetch_kev(ok).entries
    bad = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    with pytest.raises(KevError):
        fetch_kev(bad)
    down = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    with pytest.raises(KevError):
        fetch_kev(down)
