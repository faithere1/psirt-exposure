"""CISA Known Exploited Vulnerabilities (KEV) catalog.

The feed is public JSON; psirt-exposure only flags rule CVEs that appear in it. A KEV hit does not
change the verdict: it says the CVE is exploited in the wild, so an AFFECTED result is urgent.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KevError(RuntimeError):
    """The KEV feed could not be fetched or parsed."""


@dataclass(frozen=True)
class KevEntry:
    cve: str
    vendor: str
    product: str
    name: str
    date_added: str
    due_date: str
    known_ransomware_use: str
    required_action: str


@dataclass(frozen=True)
class KevCatalog:
    version: str
    released: str
    entries: dict[str, KevEntry]

    def lookup(self, cves: Iterable[str]) -> list[KevEntry]:
        return [self.entries[c] for c in sorted(set(cves)) if c in self.entries]


def parse_kev(data: Any) -> KevCatalog:
    try:
        records = data["vulnerabilities"]
        entries = {
            r["cveID"]: KevEntry(
                cve=r["cveID"],
                vendor=r.get("vendorProject", ""),
                product=r.get("product", ""),
                name=r.get("vulnerabilityName", ""),
                date_added=r.get("dateAdded", ""),
                due_date=r.get("dueDate", ""),
                known_ransomware_use=r.get("knownRansomwareCampaignUse", "Unknown"),
                required_action=r.get("requiredAction", ""),
            )
            for r in records
        }
    except (KeyError, TypeError) as exc:
        raise KevError(f"not a KEV catalog: {exc}") from None
    return KevCatalog(
        version=str(data.get("catalogVersion", "")),
        released=str(data.get("dateReleased", "")),
        entries=entries,
    )


def load_kev(path: Path) -> KevCatalog:
    return parse_kev(json.loads(path.read_text(encoding="utf-8")))


def fetch_kev(http: httpx.Client | None = None, url: str = KEV_URL) -> KevCatalog:
    client = http or httpx.Client(timeout=60.0, follow_redirects=True)
    try:
        response = client.get(url)
        response.raise_for_status()
        data = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise KevError(f"cannot fetch KEV catalog from {url}: {exc}") from None
    return parse_kev(data)
