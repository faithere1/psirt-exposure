"""Regression tests for the 2026-10-30 external security review (SEC-01..SEC-07)."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from psirt_exposure.matcher import parse_vlan_list
from psirt_exposure.netbox import NetBoxError
from psirt_exposure.netbox.client import NetBoxClient
from psirt_exposure.redact import MASK, redact
from psirt_exposure.rules.loader import load_rules
from psirt_exposure.rules.model import RuntimeCheck

# Every value below is fake.
LEAKS = [
    ("snmp-server community 7 0822455D0A16 RO", "0822455D0A16"),
    ("snmp-server community 0 PlainSecretComm RO", "PlainSecretComm"),
    ("snmp-server user u G v3 auth sha 2 256 ShaSecret priv aes 256 AesSecret", "ShaSecret"),
    ("snmp-server user u G v3 auth sha 2 256 ShaSecret priv aes 256 AesSecret", "AesSecret"),
    ("snmp-server user u G v3 encrypted auth sha 7 094F471A1A0A", "094F471A1A0A"),
    ("pre-shared-key local hex DEADBEEF12345678", "DEADBEEF12345678"),
    ("pre-shared-key address 192.0.2.1 key KeyringSecret", "KeyringSecret"),
    ("radius-server host 192.0.2.1 key RadiusSecret", "RadiusSecret"),
    ("standby 1 authentication md5 key-string HsrpSecret", "HsrpSecret"),
    ("snmp-server host 192.0.2.10 version 2c TrapSecret", "TrapSecret"),
    ("snmp-server host 192.0.2.10 TrapSecret2", "TrapSecret2"),
    ('username admin secret 0 "My Quoted Secret"', "Quoted"),
    ("crypto isakmp key 6 IsakmpSecret address 192.0.2.5", "IsakmpSecret"),
    ("l2tp tunnel password 7 0000EXAMPLE0000", "0000EXAMPLE0000"),
]


@pytest.mark.parametrize(("line", "secret"), LEAKS)
def test_redact_covers_variants(line: str, secret: str) -> None:
    out = redact(line)
    assert secret not in out
    assert MASK in out


@pytest.mark.parametrize(
    "line",
    ["crypto key generate rsa modulus 2048", "key chain KC-OSPF", "crypto ikev2 keyring KR"],
)
def test_redact_leaves_non_secrets(line: str) -> None:
    assert redact(line) == line


def _client(pages: dict[str, dict[str, object]], seen: list[str]) -> NetBoxClient:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json=pages[request.url.path])

    http = httpx.Client(transport=httpx.MockTransport(handler))
    return NetBoxClient("https://netbox.example.net", "fake-token", http=http)


def test_netbox_next_link_is_pinned_to_configured_origin() -> None:
    seen: list[str] = []
    pages = {
        "/api/dcim/devices/": {
            "results": [{"id": 1}],
            "next": "http://netbox.example.net/api/dcim/devices/?limit=200&offset=200",
        },
        "/api/dcim/devices/2/": {"results": [], "next": None},
    }
    pages["/api/dcim/devices/"]["next"] = "http://netbox.example.net/api/dcim/devices/2/?offset=1"
    client = _client(pages, seen)
    assert [d["id"] for d in client.list("dcim/devices")] == [1]
    assert seen[1].startswith("https://netbox.example.net/api/dcim/devices/2/")


@pytest.mark.parametrize(
    "link",
    ["https://attacker.example.org/api/dcim/devices/", "https://netbox.example.net/admin/"],
)
def test_netbox_next_link_to_other_host_or_path_is_refused(link: str) -> None:
    seen: list[str] = []
    client = _client({"/api/dcim/devices/": {"results": [], "next": link}}, seen)
    with pytest.raises(NetBoxError):
        list(client.list("dcim/devices"))
    assert len(seen) == 1


def test_netbox_pagination_loop_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("psirt_exposure.netbox.client.MAX_PAGES", 3)
    loop = "https://netbox.example.net/api/dcim/devices/"
    client = _client({"/api/dcim/devices/": {"results": [], "next": loop}}, [])
    with pytest.raises(NetBoxError):
        list(client.list("dcim/devices"))


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("-20", set()),
        ("1-2-3", set()),
        ("1-999999999", set()),
        ("5-3", set()),
        ("1,3-4", {1, 3, 4}),
    ],
)
def test_parse_vlan_list_rejects_malformed(text: str, expected: set[int]) -> None:
    assert parse_vlan_list(text) == expected


def test_draft_rules_are_skipped_when_reviewed_only(tmp_path: Path) -> None:
    src = Path("rules/webui.yaml").read_text(encoding="utf-8")
    (tmp_path / "webui.yaml").write_text(src.replace("status: reviewed", "status: draft"))
    assert load_rules(tmp_path) != {}
    assert load_rules(tmp_path, reviewed_only=True) == {}


@pytest.mark.parametrize("command", ["reload", "write erase", "configure terminal", "show"])
def test_runtime_check_command_must_be_show(command: str) -> None:
    with pytest.raises(ValidationError):
        RuntimeCheck(command=command, description="x")
    assert RuntimeCheck(command="show iox-service", description="x").command
