"""NetBox inventory and seed script against an in-memory fake NetBox (offline).

The fake serves the REST endpoints the seed and the inventory use (list with filters and
pagination, create, update). Tokens below are fake.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from psirt_exposure.cli import main, run_check
from psirt_exposure.inventory import load_devices
from psirt_exposure.netbox import (
    CONFIG_FIELD,
    VERSION_FIELD,
    NetBoxClient,
    NetBoxError,
    NetBoxInventory,
    load_netbox_devices,
    netbox_from_env,
)
from psirt_exposure.netbox.client import auth_header
from psirt_exposure.netbox.secrets import lab_secrets
from psirt_exposure.netbox.seed import read_seed_devices, seed_netbox, slugify
from psirt_exposure.rules import load_rules

ROOT = Path(__file__).resolve().parent.parent
CONFIGS = ROOT / "samples/configs"
RULES = ROOT / "rules"
URL = "http://netbox.example.test"
FAKE_TOKEN = "nbt_fakekey0000.fake-netbox-secret-0000"


class FakeNetBox:
    """Just enough of the NetBox REST API, with nested refs like the real one."""

    def __init__(self, page_size: int = 3) -> None:
        self.objects: dict[str, dict[int, dict[str, Any]]] = {}
        self.next_id = 1
        self.page_size = page_size
        self.auth: set[str] = set()

    def _nested(self, path: str, data: dict[str, Any]) -> dict[str, Any]:
        out = dict(data)
        for key, ref_path in (
            ("device_type", "dcim/device-types"),
            ("site", "dcim/sites"),
            ("role", "dcim/device-roles"),
            ("platform", "dcim/platforms"),
            ("manufacturer", "dcim/manufacturers"),
        ):
            if isinstance(out.get(key), int):
                ref = self.objects[ref_path][out[key]]
                out[key] = {"id": ref["id"], "slug": ref.get("slug"), "name": ref.get("name")}
        if path == "dcim/devices":
            fields = {VERSION_FIELD: None, CONFIG_FIELD: None}
            fields.update(out.get("custom_fields") or {})
            out["custom_fields"] = fields
        return out

    @staticmethod
    def _matches(obj: dict[str, Any], query: dict[str, list[str]]) -> bool:
        for key, values in query.items():
            if key in ("limit", "offset"):
                continue
            if key.endswith("_id"):
                ref = obj.get(key[:-3])
                if not ref or str(ref["id"]) not in values:
                    return False
            elif key in ("site", "platform", "role"):
                if not obj.get(key) or obj[key]["slug"] not in values:
                    return False
            elif str(obj.get(key)) not in values:
                return False
        return True

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.auth.add(request.headers.get("Authorization", ""))
        parts = urlsplit(str(request.url))
        path = parts.path.removeprefix("/api/").strip("/")
        table = None
        obj_id = None
        if path.rsplit("/", 1)[-1].isdigit():
            path, raw_id = path.rsplit("/", 1)
            obj_id = int(raw_id)
        table = self.objects.setdefault(path, {})
        if request.method == "GET":
            query = parse_qs(parts.query)
            hits = [o for o in table.values() if self._matches(o, query)]
            offset = int(query.get("offset", ["0"])[0])
            page = hits[offset : offset + self.page_size]
            nxt = None
            if offset + self.page_size < len(hits):
                nxt = f"{URL}/api/{path}/?{parts.query.split('&offset=')[0]}"
                nxt += f"&offset={offset + self.page_size}"
            return httpx.Response(200, json={"count": len(hits), "next": nxt, "results": page})
        body = json.loads(request.content)
        if request.method == "POST":
            obj = self._nested(path, {**body, "id": self.next_id})
            table[self.next_id] = obj
            self.next_id += 1
            return httpx.Response(201, json=obj)
        if request.method == "PATCH" and obj_id in table:
            merged = {**table[obj_id], **body}
            merged["custom_fields"] = {
                **table[obj_id].get("custom_fields", {}),
                **body.get("custom_fields", {}),
            }
            table[obj_id] = self._nested(path, merged)
            return httpx.Response(200, json=table[obj_id])
        return httpx.Response(404, json={"detail": "Not found."})


def _client(fake: FakeNetBox) -> NetBoxClient:
    return NetBoxClient(URL, FAKE_TOKEN, http=httpx.Client(transport=httpx.MockTransport(fake)))


@pytest.fixture
def seeded() -> FakeNetBox:
    fake = FakeNetBox()
    assert seed_netbox(_client(fake), CONFIGS, log=lambda _: None) == 8
    return fake


def test_netbox_devices_equal_file_devices(seeded: FakeNetBox) -> None:
    assert load_netbox_devices(_client(seeded)) == load_devices(CONFIGS)


def test_netbox_verdicts_equal_file_verdicts(seeded: FakeNetBox) -> None:
    rules = list(load_rules(RULES).values())
    via_netbox = run_check(load_netbox_devices(_client(seeded)), rules)
    via_files = run_check(load_devices(CONFIGS), rules)
    assert [(r.device.name, r.result) for r in via_netbox] == [
        (r.device.name, r.result) for r in via_files
    ]


def test_seed_is_idempotent(seeded: FakeNetBox) -> None:
    counts = {path: len(objs) for path, objs in seeded.objects.items()}
    seed_netbox(_client(seeded), CONFIGS, log=lambda _: None)
    assert {path: len(objs) for path, objs in seeded.objects.items()} == counts
    assert counts["dcim/devices"] == 8
    assert counts["dcim/device-types"] == 8


def test_seed_device_type_carries_pid(seeded: FakeNetBox) -> None:
    types = {t["slug"]: t for t in seeded.objects["dcim/device-types"].values()}
    assert types["isr4451-x-k9"]["part_number"] == "ISR4451-X/K9"


def test_v2_token_uses_bearer(seeded: FakeNetBox) -> None:
    assert seeded.auth == {f"Bearer {FAKE_TOKEN}"}
    assert auth_header("0123456789abcdef") == "Token 0123456789abcdef"


def test_device_without_version_has_no_facts(tmp_path: Path) -> None:
    (tmp_path / "lab-rtr").mkdir()
    (tmp_path / "lab-rtr/running-config.txt").write_text("hostname lab-rtr\n", encoding="utf-8")
    (tmp_path / "notes").mkdir()  # no running config: ignored
    assert [d.pid for d in read_seed_devices(tmp_path)] == [None]
    fake = FakeNetBox()
    seed_netbox(_client(fake), tmp_path, log=lambda _: None)
    assert load_netbox_devices(_client(fake)) == load_devices(tmp_path)
    assert load_netbox_devices(_client(fake))[0].facts is None


def test_device_without_config_is_skipped(seeded: FakeNetBox) -> None:
    device = next(iter(seeded.objects["dcim/devices"].values()))
    device["custom_fields"][CONFIG_FIELD] = None
    warnings: list[str] = []
    devices = NetBoxInventory(_client(seeded), warn=warnings.append).devices()
    assert len(devices) == 7
    assert warnings == [f"skipping {device['name']}: custom field 'running_config' is empty"]


def test_filters_are_passed_through(seeded: FakeNetBox) -> None:
    assert len(load_netbox_devices(_client(seeded), {"site": "psirt-lab"})) == 8
    assert load_netbox_devices(_client(seeded), {"site": "elsewhere"}) == []
    names = [d.name for d in load_netbox_devices(_client(seeded), {"name": ["ind-sw-01"]})]
    assert names == ["ind-sw-01"]


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx.Response(403, json={"detail": "Invalid v2 token"}), "rejected the API token"),
        (httpx.Response(500, text="boom"), "HTTP 500"),
        (httpx.Response(200, json={"unexpected": True}), "unexpected list response"),
    ],
)
def test_client_errors(response: httpx.Response, message: str) -> None:
    client = NetBoxClient(
        URL, FAKE_TOKEN, http=httpx.Client(transport=httpx.MockTransport(lambda r: response))
    )
    with pytest.raises(NetBoxError, match=message) as exc:
        list(client.list("dcim/devices"))
    assert FAKE_TOKEN not in str(exc.value)


def test_unreachable_netbox() -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    client = NetBoxClient(URL, FAKE_TOKEN, http=httpx.Client(transport=httpx.MockTransport(down)))
    with pytest.raises(NetBoxError, match="cannot reach NetBox"):
        list(client.list("dcim/devices"))


def test_client_repr_hides_token() -> None:
    assert FAKE_TOKEN not in repr(NetBoxClient(URL, FAKE_TOKEN))


def test_netbox_from_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NETBOX_URL", raising=False)
    monkeypatch.delenv("NETBOX_TOKEN", raising=False)
    env = tmp_path / ".env"
    assert netbox_from_env(env) is None
    env.write_text(f"NETBOX_URL={URL}/\nNETBOX_TOKEN={FAKE_TOKEN}\n", encoding="utf-8")
    client = netbox_from_env(env)
    assert client is not None
    assert client.url == URL


def test_slugify() -> None:
    assert slugify("ISR4451-X/K9") == "isr4451-x-k9"


def test_lab_secrets_are_compose_safe() -> None:
    values = lab_secrets()
    assert all(v.replace("_", "").replace(".", "").isalnum() for v in values.values())
    assert values["NETBOX_TOKEN"] == f"nbt_{values['NETBOX_API_KEY']}.{values['NETBOX_API_SECRET']}"
    assert lab_secrets() != values


def test_cli_netbox(
    seeded: FakeNetBox, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("psirt_exposure.check.netbox_from_env", lambda env_file: _client(seeded))
    base = ["check", "--offline", "--rules", str(RULES), "--format", "json"]
    base += ["--advisories", str(ROOT / "tests/fixtures/psirt")]
    assert main([*base, "--configs", str(CONFIGS)]) == 0
    from_files = capsys.readouterr().out
    assert main([*base, "--netbox", "--netbox-filter", "site=psirt-lab"]) == 0
    assert capsys.readouterr().out == from_files


def test_cli_netbox_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("NETBOX_URL", raising=False)
    monkeypatch.delenv("NETBOX_TOKEN", raising=False)
    env = ["--env-file", str(tmp_path / ".env")]
    base = ["check", "--offline", "--rules", str(RULES), "--netbox", *env]
    assert main(base) == 2
    assert "NETBOX_URL and NETBOX_TOKEN" in capsys.readouterr().err
    assert main(["netbox-seed", *env]) == 2
    empty = _client(FakeNetBox())
    monkeypatch.setattr("psirt_exposure.check.netbox_from_env", lambda env_file: empty)
    assert main([*base, "--netbox-filter", "site"]) == 2
    assert "not KEY=VALUE" in capsys.readouterr().err
