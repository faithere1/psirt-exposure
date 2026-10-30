"""IOS XE running-config and show version parsing."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from netsec_check.config import ShowVersionError, parse_config, parse_show_version
from netsec_check.inventory import load_device, load_devices

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples/configs"
LABELS = yaml.safe_load((SAMPLES / "labels.yaml").read_text("utf-8"))["devices"]

CONFIG = """\
Building configuration...
!
hostname test-rtr
!
interface GigabitEthernet0/0/0
 description uplink
 ip address 192.0.2.1 255.255.255.0
 !
vpdn-group LNS
 accept-dialin
  protocol l2tp
end
"""


def test_tree_and_line_numbers() -> None:
    cfg = parse_config(CONFIG)
    texts = [cl.text for cl in cfg.lines]
    assert texts == [
        "Building configuration...",
        "hostname test-rtr",
        "interface GigabitEthernet0/0/0",
        "vpdn-group LNS",
        "end",
    ]
    intf = cfg.lines[2]
    assert intf.number == 5
    assert [c.text for c in intf.children] == [
        "description uplink",
        "ip address 192.0.2.1 255.255.255.0",
    ]
    vpdn = cfg.lines[3]
    assert [(c.number, c.text) for c in vpdn.descendants()] == [
        (10, "accept-dialin"),
        (11, "protocol l2tp"),
    ]


@pytest.mark.parametrize("name", sorted(LABELS))
def test_show_version_matches_labels(name: str) -> None:
    device = load_device(SAMPLES / name)
    assert device.facts is not None
    assert device.facts.pid == LABELS[name]["platform"]
    assert device.facts.version == LABELS[name]["version"]
    assert device.facts.hostname == name


def test_show_version_errors() -> None:
    with pytest.raises(ShowVersionError, match="Version"):
        parse_show_version("cisco C8000V (VXE) processor with 1K bytes of memory.\n")
    with pytest.raises(ShowVersionError, match="PID"):
        parse_show_version("Cisco IOS XE Software, Version 17.12.02\n")


def test_load_devices(tmp_path: Path) -> None:
    (tmp_path / "rtr-a").mkdir()
    (tmp_path / "rtr-a/running-config.txt").write_text("hostname rtr-a\n", "utf-8")
    (tmp_path / "not-a-device").mkdir()
    devices = load_devices(tmp_path)
    assert [d.name for d in devices] == ["rtr-a"]
    assert devices[0].facts is None
    assert len(load_devices(SAMPLES)) == len(LABELS)
