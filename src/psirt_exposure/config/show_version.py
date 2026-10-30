"""Extract the platform (PID) and software version from IOS XE ``show version``."""

from __future__ import annotations

import re
from dataclasses import dataclass

_VERSION_RE = re.compile(r"^Cisco IOS XE Software, Version (?P<version>\S+)", re.MULTILINE)
_PID_RE = re.compile(r"^cisco (?P<pid>\S+) .*processor", re.MULTILINE)
_HOSTNAME_RE = re.compile(r"^(?P<hostname>\S+) uptime is ", re.MULTILINE)


class ShowVersionError(ValueError):
    """``show version`` output lacks the PID or the IOS XE version."""


@dataclass(frozen=True)
class DeviceFacts:
    pid: str
    version: str
    hostname: str | None = None


def parse_show_version(text: str) -> DeviceFacts:
    version = _VERSION_RE.search(text)
    pid = _PID_RE.search(text)
    if version is None:
        raise ShowVersionError("no 'Cisco IOS XE Software, Version ...' line")
    if pid is None:
        raise ShowVersionError("no 'cisco <PID> ... processor' line")
    hostname = _HOSTNAME_RE.search(text)
    return DeviceFacts(
        pid=pid.group("pid"),
        version=version.group("version"),
        hostname=hostname.group("hostname") if hostname else None,
    )
