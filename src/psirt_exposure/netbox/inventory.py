"""Build :class:`~psirt_exposure.inventory.Device` objects from NetBox devices."""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from psirt_exposure.config import DeviceFacts, parse_config
from psirt_exposure.inventory import Device
from psirt_exposure.netbox.client import NetBoxClient, Params

CONFIG_FIELD = "running_config"
VERSION_FIELD = "software_version"


def _warn(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)


@dataclass
class NetBoxInventory:
    """Devices matching ``filters`` (NetBox query parameters, e.g. ``site``, ``platform``)."""

    client: NetBoxClient
    filters: Params = field(default_factory=dict)
    warn: Callable[[str], None] = _warn

    def _pids(self, devices: list[dict[str, Any]]) -> dict[int, str]:
        ids = sorted({d["device_type"]["id"] for d in devices if d.get("device_type")})
        if not ids:
            return {}
        types = self.client.list("dcim/device-types", {"id": [str(i) for i in ids]})
        return {t["id"]: t.get("part_number") or t.get("model") or "" for t in types}

    def devices(self) -> list[Device]:
        raw = list(self.client.list("dcim/devices", self.filters))
        pids = self._pids(raw)
        out = []
        for d in raw:
            name = d.get("name")
            fields = d.get("custom_fields") or {}
            config = fields.get(CONFIG_FIELD)
            if not name:
                self.warn(f"skipping unnamed NetBox device id {d.get('id')}")
                continue
            if not config:
                self.warn(f"skipping {name}: custom field {CONFIG_FIELD!r} is empty")
                continue
            pid = pids.get(d["device_type"]["id"], "") if d.get("device_type") else ""
            version = fields.get(VERSION_FIELD) or ""
            facts = (
                DeviceFacts(pid=pid, version=version, hostname=name) if pid and version else None
            )
            out.append(Device(name=name, config=parse_config(config), facts=facts))
        return sorted(out, key=lambda dev: dev.name)


def load_netbox_devices(client: NetBoxClient, filters: Params | None = None) -> list[Device]:
    """NetBox counterpart of :func:`psirt_exposure.inventory.load_devices`, sorted by name."""
    return NetBoxInventory(client, filters or {}).devices()
