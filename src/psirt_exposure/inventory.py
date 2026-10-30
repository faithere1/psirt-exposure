"""File-mode inventory: `<dir>/<hostname>/running-config.txt` + optional `show-version.txt`."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from psirt_exposure.config import DeviceConfig, DeviceFacts, parse_config, parse_show_version

RUNNING_CONFIG = "running-config.txt"
SHOW_VERSION = "show-version.txt"


@dataclass(frozen=True)
class Device:
    name: str
    config: DeviceConfig
    facts: DeviceFacts | None


def load_device(directory: Path) -> Device:
    config = parse_config((directory / RUNNING_CONFIG).read_text(encoding="utf-8"))
    version_file = directory / SHOW_VERSION
    facts = None
    if version_file.is_file():
        facts = parse_show_version(version_file.read_text(encoding="utf-8"))
    return Device(name=directory.name, config=config, facts=facts)


def load_devices(directory: Path) -> list[Device]:
    """Every subdirectory that holds a running config, sorted by name."""
    return [
        load_device(d)
        for d in sorted(directory.iterdir())
        if d.is_dir() and (d / RUNNING_CONFIG).is_file()
    ]
