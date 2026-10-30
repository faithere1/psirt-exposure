"""MCP server (official ``mcp`` SDK): advisory checks, rules and reports as tools.

Paths are fixed when the server starts (``ServerSettings``); tools only take device, rule and
source names, never file paths. Results carry redacted evidence only. Network sources (openVuln,
the CISA KEV feed, NetBox) are used only when a tool call asks for them; the defaults are
offline (CSAF version data from local files, no KEV).
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ResourceError, ToolError
from mcp_types import ToolAnnotations

from netsec_check import __version__
from netsec_check.check import (
    CheckResult,
    CheckSetupError,
    VersionKind,
    json_item,
    kev_source,
    load_inventory,
    run_check,
    select,
    version_source,
)
from netsec_check.inventory import Device
from netsec_check.llm.extract import rule_to_yaml
from netsec_check.report import ReportMeta, report_html, report_markdown
from netsec_check.rules import Rule, RuleLoadError, load_rules

Inventory = Literal["files", "netbox"]
KevKind = Literal["none", "cisa"]

INSTRUCTIONS = """\
netsec-check answers "is this Cisco IOS XE device actually affected by this PSIRT advisory?".
Each rule checks whether the vulnerable feature is configured; the running version decides
between AFFECTED and FIXED_VERSION. Start with list_devices / list_rules, then call check for
verdicts with evidence, or report for a Markdown/HTML report with remediation snippets.
Defaults are offline: versions="csaf" (local CSAF files) and kev="none". Use versions="openvuln"
and kev="cisa" for live data, inventory="netbox" for devices from NetBox."""

_READ_ONLY = ToolAnnotations(read_only_hint=True, idempotent_hint=True, open_world_hint=False)
# check/report may call openVuln, the CISA feed or NetBox when asked to.
_READ_ONLY_OPEN = ToolAnnotations(read_only_hint=True, idempotent_hint=True, open_world_hint=True)


@dataclass(frozen=True)
class ServerSettings:
    configs: Path = Path("samples/configs")
    rules: Path = Path("rules")
    advisories: Path = Path("tests/fixtures/psirt")
    env_file: Path = Path(".env")


class NetsecTools:
    """Tool implementations, independent of the MCP transport (and directly testable)."""

    def __init__(self, settings: ServerSettings) -> None:
        self.settings = settings

    def _rules(self) -> dict[str, Rule]:
        if not self.settings.rules.is_dir():
            raise ToolError(f"cannot load rules: {self.settings.rules} is not a directory")
        try:
            return load_rules(self.settings.rules)
        except (OSError, RuleLoadError) as exc:
            raise ToolError(f"cannot load rules: {exc}") from None

    def _devices(self, inventory: Inventory, netbox_filter: dict[str, str] | None) -> list[Device]:
        if netbox_filter and inventory != "netbox":
            raise ToolError("netbox_filter needs inventory='netbox'")
        filters = {k: [v] for k, v in (netbox_filter or {}).items()}
        try:
            return load_inventory(
                netbox=inventory == "netbox",
                configs=self.settings.configs,
                env_file=self.settings.env_file,
                netbox_filters=filters,
            )
        except CheckSetupError as exc:
            raise ToolError(str(exc)) from None

    def _run(
        self,
        devices: list[str] | None,
        rules: list[str] | None,
        inventory: Inventory,
        versions: VersionKind,
        kev: KevKind,
        netbox_filter: dict[str, str] | None,
    ) -> tuple[list[CheckResult], dict[str, Rule]]:
        all_rules = self._rules()
        all_devices = self._devices(inventory, netbox_filter)
        try:
            picked_rules = select(all_rules, rules, "rule")
            picked = select({d.name: d for d in all_devices}, devices, "device")
            source = version_source(
                versions,
                offline=False,
                advisories=self.settings.advisories,
                env_file=self.settings.env_file,
            )
            catalog = kev_source(kev, offline=False)
        except CheckSetupError as exc:
            raise ToolError(str(exc)) from None
        return run_check(picked, picked_rules, source, catalog), all_rules

    def list_devices(
        self, inventory: Inventory = "files", netbox_filter: dict[str, str] | None = None
    ) -> list[dict[str, Any]]:
        return [
            {
                "name": d.name,
                "platform": d.facts.pid if d.facts else None,
                "version": d.facts.version if d.facts else None,
            }
            for d in self._devices(inventory, netbox_filter)
        ]

    def list_rules(self) -> list[dict[str, Any]]:
        return [
            {
                "id": r.id,
                "advisory_id": r.advisory_id,
                "cves": list(r.cves),
                "title": r.title,
                "status": r.status.value,
                "summary": r.summary,
                "affected_platforms": r.affected_platforms,
                "mitigations": [m.id for m in r.mitigations],
            }
            for r in self._rules().values()
        ]

    def rule_yaml(self, rule_id: str) -> str:
        rule = self._rules().get(rule_id)
        if rule is None:
            raise ResourceError(f"unknown rule: {rule_id}")
        return rule_to_yaml(rule)

    def check(
        self,
        devices: list[str] | None = None,
        rules: list[str] | None = None,
        inventory: Inventory = "files",
        versions: VersionKind = "csaf",
        kev: KevKind = "none",
        netbox_filter: dict[str, str] | None = None,
        only_findings: bool = False,
    ) -> list[dict[str, Any]]:
        results, _ = self._run(devices, rules, inventory, versions, kev, netbox_filter)
        items = [json_item(r) for r in results]
        if only_findings:
            keep = {"AFFECTED", "INDETERMINATE", "MITIGATED"}
            items = [i for i in items if i["verdict"] in keep]
        return items

    def report(
        self,
        format: Literal["markdown", "html"] = "markdown",
        devices: list[str] | None = None,
        rules: list[str] | None = None,
        inventory: Inventory = "files",
        versions: VersionKind = "csaf",
        kev: KevKind = "none",
        netbox_filter: dict[str, str] | None = None,
    ) -> str:
        results, all_rules = self._run(devices, rules, inventory, versions, kev, netbox_filter)
        meta = ReportMeta(
            generated=dt.date.today().isoformat(),
            sources={
                "Inventory": "NetBox" if inventory == "netbox" else "files",
                "Versions": versions,
                "KEV": kev,
            },
        )
        render = report_markdown if format == "markdown" else report_html
        return render(results, all_rules, meta)


def build_server(settings: ServerSettings | None = None) -> MCPServer:
    tools = NetsecTools(settings or ServerSettings())
    server: MCPServer = MCPServer(
        name="netsec-check",
        title="netsec-check: Cisco PSIRT exposure checks",
        instructions=INSTRUCTIONS,
        version=__version__,
    )

    @server.tool(annotations=_READ_ONLY_OPEN)
    def list_devices(
        inventory: Inventory = "files", netbox_filter: dict[str, str] | None = None
    ) -> list[dict[str, Any]]:
        """List inventory devices with platform (PID) and IOS XE version.

        inventory: "files" (sample config directory) or "netbox".
        netbox_filter: NetBox device query parameters, e.g. {"site": "netsec-lab"}.
        """
        return tools.list_devices(inventory, netbox_filter)

    @server.tool(annotations=_READ_ONLY)
    def list_rules() -> list[dict[str, Any]]:
        """List the reviewed advisory rules: id, advisory, CVEs, title and exposure summary."""
        return tools.list_rules()

    @server.tool(annotations=_READ_ONLY_OPEN)
    def check(
        devices: list[str] | None = None,
        rules: list[str] | None = None,
        inventory: Inventory = "files",
        versions: VersionKind = "csaf",
        kev: KevKind = "none",
        netbox_filter: dict[str, str] | None = None,
        only_findings: bool = False,
    ) -> list[dict[str, Any]]:
        """Match advisory rules against device configs; one verdict per device and rule.

        Verdicts: AFFECTED, NOT_AFFECTED_FEATURE_DISABLED, FIXED_VERSION, MITIGATED,
        INDETERMINATE. Each item has the reason, redacted evidence lines, runtime checks to run
        on the device and CISA KEV entries.
        devices / rules: names from list_devices / list_rules (default: all).
        versions: "csaf" (local CSAF files, offline), "openvuln" (live Cisco API) or "none".
        kev: "none" or "cisa" (download the CISA KEV feed).
        only_findings: keep only AFFECTED, INDETERMINATE and MITIGATED items.
        """
        return tools.check(devices, rules, inventory, versions, kev, netbox_filter, only_findings)

    @server.tool(annotations=_READ_ONLY_OPEN)
    def report(
        format: Literal["markdown", "html"] = "markdown",
        devices: list[str] | None = None,
        rules: list[str] | None = None,
        inventory: Inventory = "files",
        versions: VersionKind = "csaf",
        kev: KevKind = "none",
        netbox_filter: dict[str, str] | None = None,
    ) -> str:
        """Render a Markdown or HTML report: summary, per-device counts, and findings with
        evidence and mitigation / remediation config snippets. Arguments as for check."""
        return tools.report(format, devices, rules, inventory, versions, kev, netbox_filter)

    @server.resource(
        "netsec://rules/{rule_id}",
        name="rule",
        description="A reviewed rule as YAML (exposure conditions, mitigations, snippets)",
        mime_type="application/yaml",
    )
    def rule_resource(rule_id: str) -> str:
        return tools.rule_yaml(rule_id)

    return server


def main() -> None:
    build_server().run("stdio")


if __name__ == "__main__":
    main()
