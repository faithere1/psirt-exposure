"""MCP server: tools and resources over an in-process client (offline sources only)."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, TypeVar

import pytest
from mcp import Client, StdioServerParameters

from psirt_exposure.cli import main
from psirt_exposure.mcp_server import ServerSettings, build_server

ROOT = Path(__file__).resolve().parent.parent
T = TypeVar("T")


@pytest.fixture
def settings(tmp_path: Path) -> ServerSettings:
    return ServerSettings(
        configs=ROOT / "samples/configs",
        rules=ROOT / "rules",
        advisories=ROOT / "tests/fixtures/psirt",
        env_file=tmp_path / ".env",
    )


def _with_client(settings: ServerSettings, fn: Callable[[Client], Awaitable[T]]) -> T:
    async def run() -> T:
        async with Client(build_server(settings)) as client:
            return await fn(client)

    return asyncio.run(run())


def _call(settings: ServerSettings, tool: str, args: dict[str, Any] | None = None) -> Any:
    async def go(client: Client) -> Any:
        return await client.call_tool(tool, args or {})

    return _with_client(settings, go)


def test_lists_tools_and_templates(settings: ServerSettings) -> None:
    async def go(client: Client) -> tuple[list[str], list[str], str | None]:
        tools = await client.list_tools()
        templates = await client.list_resource_templates()
        names = [t.name for t in tools.tools]
        uris = [t.uri_template for t in templates.resource_templates]
        return names, uris, client.instructions

    names, uris, instructions = _with_client(settings, go)
    assert names == ["list_devices", "list_rules", "check", "report"]
    assert uris == ["psirt-exposure://rules/{rule_id}"]
    assert instructions and "offline" in instructions


def test_list_devices_and_rules(settings: ServerSettings) -> None:
    devices = _call(settings, "list_devices").structured_content["result"]
    assert len(devices) == 8
    assert {"name": "edge-rtr-01", "platform": "C8300-1N1S-6T", "version": "17.09.04a"} in devices
    rules = _call(settings, "list_rules").structured_content["result"]
    assert sorted(r["id"] for r in rules) == sorted(p.stem for p in (ROOT / "rules").glob("*.yaml"))


def test_check_matches_cli_json(
    settings: ServerSettings, capsys: pytest.CaptureFixture[str]
) -> None:
    result = _call(settings, "check")
    assert not result.is_error
    items = result.structured_content["result"]
    argv = ["check", "--offline", "--format", "json", "--configs", str(settings.configs)]
    argv += ["--rules", str(settings.rules), "--advisories", str(settings.advisories)]
    assert main(argv) == 0
    assert items == json.loads(capsys.readouterr().out)


def test_check_filters(settings: ServerSettings) -> None:
    args = {"devices": ["edge-rtr-01"], "rules": ["webui", "ikev2"], "versions": "none"}
    items = _call(settings, "check", args).structured_content["result"]
    assert [(i["device"], i["rule"]) for i in items] == [
        ("edge-rtr-01", "webui"),
        ("edge-rtr-01", "ikev2"),
    ]
    findings = _call(settings, "check", {"only_findings": True}).structured_content["result"]
    assert findings and {i["verdict"] for i in findings} <= {
        "AFFECTED",
        "INDETERMINATE",
        "MITIGATED",
    }


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ({"devices": ["nope"]}, "unknown device: nope"),
        ({"rules": ["nope"]}, "unknown rule: nope"),
        ({"versions": "openvuln"}, "CISCO_CLIENT_ID"),
        ({"netbox_filter": {"site": "x"}}, "inventory='netbox'"),
        ({"inventory": "netbox"}, "NETBOX_URL and NETBOX_TOKEN"),
        ({"versions": "bogus"}, "versions"),
    ],
)
def test_check_errors(
    settings: ServerSettings, monkeypatch: pytest.MonkeyPatch, args: dict[str, Any], message: str
) -> None:
    for var in ("CISCO_CLIENT_ID", "CISCO_CLIENT_SECRET", "NETBOX_URL", "NETBOX_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    result = _call(settings, "check", args)
    assert result.is_error
    assert message in result.content[0].text


def test_report_tool(settings: ServerSettings) -> None:
    md = _call(settings, "report", {"devices": ["access-sw-01"]}).content[0].text
    assert md.startswith("# psirt-exposure report")
    assert "### access-sw-01 · webui · AFFECTED" in md
    assert "EXAMPLE-RO" not in md
    page = _call(settings, "report", {"format": "html"}).content[0].text
    assert page.startswith("<!DOCTYPE html>")


def test_rule_resource(settings: ServerSettings) -> None:
    async def go(client: Client) -> str:
        res = await client.read_resource("psirt-exposure://rules/webui")
        return res.contents[0].text  # type: ignore[union-attr]

    text = _with_client(settings, go)
    assert text.startswith("schema_version: 1\nid: webui\n")
    assert "no ip http secure-server" in text


def test_missing_rules_dir(settings: ServerSettings, tmp_path: Path) -> None:
    bad = ServerSettings(rules=tmp_path / "missing", configs=settings.configs)
    result = _call(bad, "list_rules")
    assert result.is_error and "cannot load rules" in result.content[0].text


def test_stdio_subprocess(tmp_path: Path) -> None:
    """The real ``psirt-exposure mcp`` entry point over stdio, as MCP Inspector launches it."""
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "psirt_exposure.cli", "mcp", "--env-file", str(tmp_path / ".env")],
        env={"PYTHONPATH": str(ROOT / "src"), "PATH": os.environ.get("PATH", "")},
        cwd=ROOT,
    )

    async def run() -> tuple[list[str], list[dict[str, Any]], str]:
        async with Client(params) as client:
            tools = await client.list_tools()
            check = await client.call_tool("check", {"devices": ["edge-rtr-02"]})
            report = await client.call_tool("report", {"devices": ["edge-rtr-02"]})
            return (
                [t.name for t in tools.tools],
                check.structured_content["result"],
                report.content[0].text,  # type: ignore[union-attr]
            )

    names, items, md = asyncio.run(run())
    assert names == ["list_devices", "list_rules", "check", "report"]
    assert len(items) == 10 and {i["device"] for i in items} == {"edge-rtr-02"}
    assert "### edge-rtr-02 ·" in md
