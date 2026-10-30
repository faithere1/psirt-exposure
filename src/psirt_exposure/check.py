"""Shared check pipeline for the CLI, reports and the MCP server.

``run_check`` evaluates every rule on every device; the ``*_source`` helpers build the data
sources from plain parameters and raise ``CheckSetupError`` when one is unavailable.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from psirt_exposure.inventory import Device, load_devices
from psirt_exposure.matcher import RuleResult, check_rule
from psirt_exposure.netbox import (
    TOKEN_ENV,
    URL_ENV,
    NetBoxClient,
    NetBoxError,
    load_netbox_devices,
    netbox_from_env,
)
from psirt_exposure.psirt import (
    CsafVersionSource,
    KevCatalog,
    KevEntry,
    OpenVulnClient,
    OpenVulnVersionSource,
    VersionSource,
    credentials_from_env,
    fetch_kev,
    load_kev,
)
from psirt_exposure.psirt.kev import KevError
from psirt_exposure.psirt.openvuln import CLIENT_ID_ENV, CLIENT_SECRET_ENV
from psirt_exposure.rules import Rule

VersionKind = Literal["openvuln", "csaf", "none"]


class CheckSetupError(Exception):
    """A data source for ``check`` is unavailable (CLI exit code 2)."""


@dataclass(frozen=True)
class CheckResult:
    device: Device
    result: RuleResult
    kev: tuple[KevEntry, ...] = ()


def run_check(
    devices: Sequence[Device],
    rules: Sequence[Rule],
    versions: VersionSource | None = None,
    kev: KevCatalog | None = None,
) -> list[CheckResult]:
    out = []
    for d in devices:
        for r in rules:
            affected = None
            if versions is not None and d.facts is not None:
                affected = versions.version_affected(r.advisory_id, d.facts.version)
            hits = tuple(kev.lookup(r.cves)) if kev else ()
            out.append(CheckResult(d, check_rule(r, d.config, d.facts, affected), hits))
    return out


def json_item(item: CheckResult) -> dict[str, Any]:
    """JSON-ready view of one result; evidence is the redacted ``Evidence.text``."""
    d, r = item.device, item.result
    return {
        "device": d.name,
        "platform": d.facts.pid if d.facts else None,
        "version": d.facts.version if d.facts else None,
        "rule": r.rule_id,
        "advisory_id": r.advisory_id,
        "exposure": r.exposure.value if r.exposure else None,
        "verdict": r.verdict.value,
        "reason": r.reason,
        "mitigation": r.mitigation,
        "evidence": [{"line": e.line, "text": e.text} for e in r.evidence],
        "runtime_checks": [c.model_dump() for c in r.runtime_checks],
        "kev": [
            {
                "cve": k.cve,
                "date_added": k.date_added,
                "due_date": k.due_date,
                "known_ransomware_use": k.known_ransomware_use,
            }
            for k in item.kev
        ],
    }


def select(items: Mapping[str, Any], wanted: Sequence[str] | None, what: str) -> list[Any]:
    """The named items in the given order (all items if none are named)."""
    if not wanted:
        return list(items.values())
    unknown = sorted(set(wanted) - items.keys())
    if unknown:
        raise CheckSetupError(f"unknown {what}: {', '.join(unknown)}")
    return [items[w] for w in wanted]


def version_source(
    kind: VersionKind, *, offline: bool, advisories: Path, env_file: Path
) -> VersionSource | None:
    if kind == "none":
        return None
    if kind == "csaf":
        if not advisories.is_dir():
            raise CheckSetupError(f"advisory directory {advisories} not found")
        return CsafVersionSource.from_dir(advisories)
    if offline:
        raise CheckSetupError("--versions openvuln needs the network; drop --offline")
    creds = credentials_from_env(env_file)
    if creds is None:
        raise CheckSetupError(
            f"openVuln needs {CLIENT_ID_ENV} and {CLIENT_SECRET_ENV} (environment or "
            f"{env_file}); use --offline for local CSAF version data"
        )
    return OpenVulnVersionSource(OpenVulnClient(*creds))


def kev_source(kind: str, *, offline: bool) -> KevCatalog | None:
    """``kind`` is 'none', 'cisa' (download the feed) or a local KEV JSON path."""
    if kind == "none":
        return None
    if kind == "cisa":
        if offline:
            raise CheckSetupError("--kev cisa needs the network; pass a local file with --offline")
        try:
            return fetch_kev()
        except KevError as exc:
            raise CheckSetupError(str(exc)) from None
    path = Path(kind)
    if not path.is_file():
        raise CheckSetupError(f"KEV file {path} not found")
    try:
        return load_kev(path)
    except (KevError, ValueError) as exc:
        raise CheckSetupError(f"cannot read KEV file {path}: {exc}") from None


def netbox_client(env_file: Path) -> NetBoxClient:
    client = netbox_from_env(env_file)
    if client is None:
        raise CheckSetupError(f"NetBox needs {URL_ENV} and {TOKEN_ENV} (environment or {env_file})")
    return client


def load_inventory(
    *,
    netbox: bool,
    configs: Path,
    env_file: Path,
    netbox_filters: Mapping[str, list[str]] | None = None,
) -> list[Device]:
    if not netbox:
        if not configs.is_dir():
            raise CheckSetupError(f"config directory {configs} not found")
        return load_devices(configs)
    try:
        return load_netbox_devices(netbox_client(env_file), dict(netbox_filters or {}))
    except NetBoxError as exc:
        raise CheckSetupError(str(exc)) from None
