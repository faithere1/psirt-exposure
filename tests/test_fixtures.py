"""Load and sanity-check the offline fixtures: PSIRT advisories and sample device configs."""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
PSIRT_DIR = ROOT / "tests" / "fixtures" / "psirt"
CONFIGS_DIR = ROOT / "samples" / "configs"

LABEL_VALUES = {"present", "absent", "mitigated", "not_applicable_platform"}
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
# Word-boundary guards keep version strings such as "universalk9.17.09.04a" out.
IPV4_RE = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
# Value after a secret keyword, skipping an optional encryption type digit ("secret 9 ...").
SECRET_RE = re.compile(r"\b(?:secret|key|password)\s+(?:\d\s+)?(\S+)")
VERSION_RE = re.compile(r"^Cisco IOS XE Software, Version (\S+)$", re.MULTILINE)


def _load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


MANIFEST = _load_yaml(PSIRT_DIR / "manifest.yaml")
ADVISORIES: list[dict[str, Any]] = MANIFEST["advisories"]
LABELS = _load_yaml(CONFIGS_DIR / "labels.yaml")
DEVICES: dict[str, dict[str, Any]] = LABELS["devices"]


def _notes(csaf: dict[str, Any]) -> dict[str, str]:
    return {n["title"]: n["text"] for n in csaf["document"]["notes"] if "title" in n}


def test_manifest_has_ten_unique_advisories() -> None:
    assert len(ADVISORIES) == 10
    assert len({a["key"] for a in ADVISORIES}) == 10
    assert len({a["id"] for a in ADVISORIES}) == 10


def test_manifest_matches_files() -> None:
    files = {p.stem for p in PSIRT_DIR.glob("*.json")}
    assert files == {a["id"] for a in ADVISORIES}


@pytest.mark.parametrize("adv", ADVISORIES, ids=lambda a: a["key"])
def test_csaf_fixture_loads(adv: dict[str, Any]) -> None:
    csaf = json.loads((PSIRT_DIR / f"{adv['id']}.json").read_text(encoding="utf-8"))
    doc = csaf["document"]
    assert doc["csaf_version"] == "2.0"
    assert doc["tracking"]["id"] == adv["id"]
    assert sorted(v["cve"] for v in csaf["vulnerabilities"]) == sorted(adv["cves"])
    notes = _notes(csaf)
    assert "IOS XE" in notes.get("Vulnerable Products", "")
    # Feature conditions live in "Vulnerable Products"; the LLM phase depends on it.
    assert len(notes.get("Vulnerable Products", "")) > 200
    assert "Workarounds" in notes


def test_labels_cover_every_device_and_advisory() -> None:
    keys = {a["key"] for a in ADVISORIES}
    dirs = {p.name for p in CONFIGS_DIR.iterdir() if p.is_dir()}
    assert 6 <= len(DEVICES) <= 8
    assert set(DEVICES) == dirs
    for name, dev in DEVICES.items():
        assert set(dev["labels"]) == keys, name
        assert set(dev["labels"].values()) <= LABEL_VALUES, name
        assert set(dev.get("notes", {})) <= keys, name


def test_every_advisory_has_positive_and_negative_label() -> None:
    for adv in ADVISORIES:
        values = {dev["labels"][adv["key"]] for dev in DEVICES.values()}
        assert "present" in values, adv["key"]
        assert "absent" in values, adv["key"]


@pytest.mark.parametrize("name", sorted(DEVICES))
def test_sample_device_files(name: str) -> None:
    dev = DEVICES[name]
    config = (CONFIGS_DIR / name / "running-config.txt").read_text(encoding="utf-8")
    show_ver = (CONFIGS_DIR / name / "show-version.txt").read_text(encoding="utf-8")
    assert f"\nhostname {name}\n" in config
    assert config.rstrip().endswith("end")
    match = VERSION_RE.search(show_ver)
    assert match is not None
    assert match.group(1) == dev["version"]
    assert f"cisco {dev['platform']} " in show_ver
    assert f"{name} uptime is" in show_ver


@pytest.mark.parametrize("name", sorted(DEVICES))
def test_samples_use_only_documentation_addresses(name: str) -> None:
    for path in sorted((CONFIGS_DIR / name).iterdir()):
        for raw in IPV4_RE.findall(path.read_text(encoding="utf-8")):
            addr = ipaddress.ip_address(raw)
            # Masks, wildcards and the default route are not host addresses.
            if raw.startswith(("255.", "0.")):
                continue
            assert any(addr in net for net in DOC_NETS), f"{path.name}: {raw}"


@pytest.mark.parametrize("name", sorted(DEVICES))
def test_samples_use_only_fake_secrets(name: str) -> None:
    config = (CONFIGS_DIR / name / "running-config.txt").read_text(encoding="utf-8")
    values = SECRET_RE.findall(config)
    assert values, "expected at least one (fake) secret"
    for value in values:
        assert re.search(r"EXAMPLE|EXAM\$", value), value
