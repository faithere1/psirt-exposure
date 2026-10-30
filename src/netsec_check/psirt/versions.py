"""Is a software version affected by an advisory? (the ``version_affected`` input of the matcher)

Two deterministic sources answer this; the LLM never does:

* ``OpenVulnVersionSource`` (live): the openVuln OS-version endpoint lists every advisory that
  affects a version; one request per distinct version.
* ``CsafVersionSource`` (offline): the ``known_affected`` product status of local CSAF files,
  restricted to the "Cisco IOS XE Software" product family.

Both return ``True`` (affected), ``False`` (version not listed: fixed or never affected) or
``None`` (unknown: no data for the advisory, or the lookup failed).

Cisco does not evaluate releases that are past end of maintenance, so a CSAF file can omit a
version without it being fixed. The CSAF source therefore answers ``False`` only when the
device's release train (``17.9``) is listed in the advisory or is newer than every listed train
(released after the advisory, so the fix is inherited); an unlisted older train gives ``None``.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from netsec_check.psirt.openvuln import OpenVulnClient, OpenVulnError

IOS_XE_FAMILY = "Cisco IOS XE Software"
_LEADING_ZEROS = re.compile(r"^0+(?=\d)")
_TRAIN_RE = re.compile(r"^(\d+)\.(\d+)\.\d+[a-z]?$")


def normalize_version(version: str) -> str:
    """``show version`` style ``17.09.03a`` -> openVuln / CSAF style ``17.9.3a``."""
    return ".".join(_LEADING_ZEROS.sub("", part) for part in version.strip().split("."))


def _key(version: str) -> str:
    return normalize_version(version).casefold()


def release_train(version: str) -> tuple[int, int] | None:
    """``17.09.03a`` -> ``(17, 9)``; None for ``3.x.yS`` and special builds (``17.11.99SW``)."""
    m = _TRAIN_RE.match(normalize_version(version))
    if m is None or int(m.group(1)) < 16:
        return None
    return int(m.group(1)), int(m.group(2))


class VersionSource(Protocol):
    @property
    def name(self) -> str: ...

    def version_affected(self, advisory_id: str, version: str) -> bool | None: ...


def _family_products(branch: dict[str, Any]) -> dict[str, str]:
    """product_id -> name for every product below ``branch``."""
    found: dict[str, str] = {}
    for child in branch.get("branches") or []:
        product = child.get("product")
        if product:
            found[product["product_id"]] = product["name"]
        found.update(_family_products(child))
    return found


def _find_family(branch: dict[str, Any], name: str) -> list[dict[str, Any]]:
    matches = []
    for child in branch.get("branches") or []:
        if child.get("category") == "product_family" and child.get("name") == name:
            matches.append(child)
        else:
            matches.extend(_find_family(child, name))
    return matches


@dataclass(frozen=True)
class CsafVersions:
    """IOS XE versions an advisory lists as affected, and the release trains it covers."""

    affected: frozenset[str]
    trains: frozenset[tuple[int, int]]

    def version_affected(self, version: str) -> bool | None:
        if _key(version) in self.affected:
            return True
        train = release_train(version)
        if train is None or train in self.trains or not self.trains:
            return False
        return False if train > max(self.trains) else None


def csaf_affected_versions(csaf: dict[str, Any]) -> CsafVersions | None:
    """Affected IOS XE versions from ``known_affected``; None if the CSAF has no IOS XE family."""
    tree = csaf.get("product_tree", {})
    families = _find_family(tree, IOS_XE_FAMILY)
    if not families:
        return None
    products: dict[str, str] = {}
    for family in families:
        products.update(_family_products(family))
    trains = {t for name in products.values() if (t := release_train(name)) is not None}
    # Relationship products ("<version> when installed on <platform>") count for their version.
    for rel in tree.get("relationships") or []:
        ref = rel.get("product_reference")
        if ref in products:
            products[rel["full_product_name"]["product_id"]] = products[ref]
    affected: set[str] = set()
    for vuln in csaf.get("vulnerabilities", []):
        affected.update(vuln.get("product_status", {}).get("known_affected", []))
    return CsafVersions(
        affected=frozenset(_key(name) for pid, name in products.items() if pid in affected),
        trains=frozenset(trains),
    )


class CsafVersionSource:
    """Offline source: local CSAF files, keyed by advisory id (the file stem)."""

    name = "csaf"

    def __init__(self, files: dict[str, Path]) -> None:
        self._files = files
        self._cache: dict[str, CsafVersions | None] = {}

    @classmethod
    def from_dir(cls, directory: Path) -> CsafVersionSource:
        return cls({p.stem: p for p in sorted(directory.glob("cisco-sa-*.json"))})

    def affected_versions(self, advisory_id: str) -> CsafVersions | None:
        if advisory_id not in self._cache:
            path = self._files.get(advisory_id)
            self._cache[advisory_id] = (
                csaf_affected_versions(json.loads(path.read_text(encoding="utf-8")))
                if path
                else None
            )
        return self._cache[advisory_id]

    def version_affected(self, advisory_id: str, version: str) -> bool | None:
        versions = self.affected_versions(advisory_id)
        return None if versions is None else versions.version_affected(version)


def _warn(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)


class OpenVulnVersionSource:
    """Live source: one openVuln OS-version request per distinct version, cached."""

    name = "openvuln"

    def __init__(
        self,
        client: OpenVulnClient,
        os_type: str = "iosxe",
        warn: Callable[[str], None] = _warn,
    ) -> None:
        self.client = client
        self.os_type = os_type
        self._warn = warn
        self._cache: dict[str, frozenset[str] | None] = {}

    def advisory_ids(self, version: str) -> frozenset[str] | None:
        key = normalize_version(version)
        if key not in self._cache:
            try:
                found = self.client.advisories_for_version(key, self.os_type)
                self._cache[key] = frozenset(a.advisory_id for a in found)
            except OpenVulnError as exc:
                self._warn(f"openVuln lookup for {self.os_type} {key} failed: {exc}")
                self._cache[key] = None
        return self._cache[key]

    def version_affected(self, advisory_id: str, version: str) -> bool | None:
        ids = self.advisory_ids(version)
        return None if ids is None else advisory_id in ids
