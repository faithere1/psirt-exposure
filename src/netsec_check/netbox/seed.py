"""Load a file-mode inventory (``samples/configs``) into NetBox. Idempotent: re-running updates.

Creates, if missing: manufacturer, site, device role, platform, the two custom fields on
``dcim.device`` and one device type per PID; then creates or updates every device.
Devices without ``show version`` get a placeholder device type with no part number and an empty
version, so the NetBox inventory reports no facts for them, exactly like file mode.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from netsec_check.config import parse_show_version
from netsec_check.inventory import RUNNING_CONFIG, SHOW_VERSION
from netsec_check.netbox.client import NetBoxClient
from netsec_check.netbox.inventory import CONFIG_FIELD, VERSION_FIELD

MANUFACTURER = {"name": "Cisco", "slug": "cisco"}
SITE = {"name": "netsec-lab", "slug": "netsec-lab", "status": "active"}
ROLE = {"name": "Network device", "slug": "network-device", "color": "2196f3"}
PLATFORM = {"name": "Cisco IOS XE", "slug": "cisco-ios-xe"}
UNKNOWN_TYPE = "unknown"
CUSTOM_FIELDS = (
    {
        "name": VERSION_FIELD,
        "label": "Software version",
        "type": "text",
        "object_types": ["dcim.device"],
        "description": "OS version as printed by 'show version' (netsec-check)",
    },
    {
        "name": CONFIG_FIELD,
        "label": "Running config",
        "type": "longtext",
        "object_types": ["dcim.device"],
        "ui_visible": "hidden",
        "description": "Running configuration (netsec-check)",
    },
)


def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


@dataclass(frozen=True)
class SeedDevice:
    name: str
    pid: str | None
    version: str | None
    config: str


def read_seed_devices(directory: Path) -> list[SeedDevice]:
    """Raw device data from a file-mode inventory directory, sorted by name."""
    out = []
    for d in sorted(directory.iterdir()):
        if not (d.is_dir() and (d / RUNNING_CONFIG).is_file()):
            continue
        pid = version = None
        if (d / SHOW_VERSION).is_file():
            facts = parse_show_version((d / SHOW_VERSION).read_text(encoding="utf-8"))
            pid, version = facts.pid, facts.version
        config = (d / RUNNING_CONFIG).read_text(encoding="utf-8")
        out.append(SeedDevice(d.name, pid, version, config))
    return out


class Seeder:
    def __init__(self, client: NetBoxClient, log: Callable[[str], None] = print) -> None:
        self.client = client
        self.log = log

    def ensure(self, path: str, lookup: Mapping[str, str], data: Mapping[str, Any]) -> int:
        """Id of the object matching ``lookup``; create it from ``data`` if missing."""
        found = list(self.client.list(path, lookup))
        if found:
            return int(found[0]["id"])
        self.log(f"create {path} {next(iter(lookup.values()))}")
        return int(self.client.create(path, data)["id"])

    def device_type(self, manufacturer: int, pid: str | None) -> int:
        model = pid or UNKNOWN_TYPE
        data = {"manufacturer": manufacturer, "model": model, "slug": slugify(model)}
        if pid:
            data["part_number"] = pid
        return self.ensure("dcim/device-types", {"slug": slugify(model)}, data)

    def seed(self, devices: list[SeedDevice]) -> None:
        for cf in CUSTOM_FIELDS:
            self.ensure("extras/custom-fields", {"name": str(cf["name"])}, cf)
        manufacturer = self.ensure(
            "dcim/manufacturers", {"slug": MANUFACTURER["slug"]}, MANUFACTURER
        )
        site = self.ensure("dcim/sites", {"slug": SITE["slug"]}, SITE)
        role = self.ensure("dcim/device-roles", {"slug": ROLE["slug"]}, ROLE)
        platform = self.ensure(
            "dcim/platforms", {"slug": PLATFORM["slug"]}, {**PLATFORM, "manufacturer": manufacturer}
        )
        for dev in devices:
            data = {
                "name": dev.name,
                "device_type": self.device_type(manufacturer, dev.pid),
                "role": role,
                "site": site,
                "platform": platform,
                "status": "active",
                "custom_fields": {VERSION_FIELD: dev.version or "", CONFIG_FIELD: dev.config},
            }
            existing = list(
                self.client.list("dcim/devices", {"name": dev.name, "site_id": str(site)})
            )
            if existing:
                self.client.update("dcim/devices", int(existing[0]["id"]), data)
                self.log(f"update dcim/devices {dev.name}")
            else:
                self.client.create("dcim/devices", data)
                self.log(f"create dcim/devices {dev.name}")


def seed_netbox(client: NetBoxClient, directory: Path, log: Callable[[str], None] = print) -> int:
    """Seed every device under ``directory``; returns the number of devices."""
    devices = read_seed_devices(directory)
    Seeder(client, log).seed(devices)
    return len(devices)
