"""Advisory text for the LLM, taken from a Cisco CSAF 2.0 document.

Only the sections that describe *when* a device is exposed are sent to the model. Identifiers
(advisory id, CVEs, title) are copied deterministically and never generated.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

# Sections that state the feature condition, platforms and workarounds. Fixed Software,
# legal text and the policy boilerplate are left out: versions come from openVuln, not the LLM.
PROMPT_SECTIONS = (
    "Summary",
    "Vulnerable Products",
    "Products Confirmed Not Vulnerable",
    "Workarounds",
)


@dataclass(frozen=True)
class AdvisoryText:
    advisory_id: str
    cves: tuple[str, ...]
    title: str
    sections: dict[str, str]

    def prompt_text(self) -> str:
        parts = [f"Advisory: {self.advisory_id}", f"Title: {self.title}"]
        for name in PROMPT_SECTIONS:
            text = self.sections.get(name)
            if text:
                body = "\n".join(line.rstrip() for line in text.replace("\r\n", "\n").split("\n"))
                parts.append(f"## {name}\n{body.strip()}")
        return "\n\n".join(parts)


def advisory_from_csaf(csaf: dict[str, Any]) -> AdvisoryText:
    doc = csaf["document"]
    sections = {n["title"]: n["text"] for n in doc.get("notes", []) if "title" in n}
    return AdvisoryText(
        advisory_id=doc["tracking"]["id"],
        cves=tuple(sorted(v["cve"] for v in csaf.get("vulnerabilities", []) if "cve" in v)),
        title=doc["title"],
        sections=sections,
    )


def load_csaf(path: Path) -> AdvisoryText:
    return advisory_from_csaf(json.loads(path.read_text(encoding="utf-8")))


def load_manifest(path: Path) -> dict[str, Path]:
    """Map advisory keys to CSAF files from a fixture ``manifest.yaml``."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return {a["key"]: path.parent / f"{a['id']}.json" for a in data["advisories"]}
