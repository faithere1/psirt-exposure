"""NetBox inventory: devices, platform (PID) and software version from the NetBox REST API.

Data model (created by :mod:`netsec_check.netbox.seed`):

- device type ``part_number`` (falling back to ``model``) is the PID;
- custom field ``software_version`` (text) holds the IOS XE version as ``show version`` prints it;
- custom field ``running_config`` (long text) holds the running configuration.

:func:`load_netbox_devices` returns the same :class:`~netsec_check.inventory.Device` objects as
the file-mode :func:`~netsec_check.inventory.load_devices`.
"""

from netsec_check.netbox.client import (
    TOKEN_ENV,
    URL_ENV,
    NetBoxClient,
    NetBoxError,
    netbox_from_env,
)
from netsec_check.netbox.inventory import (
    CONFIG_FIELD,
    VERSION_FIELD,
    NetBoxInventory,
    load_netbox_devices,
)

__all__ = [
    "CONFIG_FIELD",
    "TOKEN_ENV",
    "URL_ENV",
    "VERSION_FIELD",
    "NetBoxClient",
    "NetBoxError",
    "NetBoxInventory",
    "load_netbox_devices",
    "netbox_from_env",
]
