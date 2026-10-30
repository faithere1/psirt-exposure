"""Drift detection for ``watch``: compare check results with a saved snapshot.

A snapshot keeps, per device and rule, the verdict, exposure, mitigation, redacted evidence text
and KEV CVEs. Evidence line numbers are left out on purpose: an unrelated edit higher up in the
config shifts them without changing exposure. Changes come from the device configs (config
drift), the advisory and version data (advisory drift) or the rules themselves.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from psirt_exposure.check import CheckResult

SNAPSHOT_VERSION = 1


class DriftError(ValueError):
    """The state file is unreadable or from an unknown format version."""


class ChangeKind(StrEnum):
    NEW = "new"  # device x rule pair not in the baseline (new device or rule)
    GONE = "gone"  # pair no longer checked
    VERDICT = "verdict"  # verdict changed
    EVIDENCE = "evidence"  # same verdict, different exposure, mitigation or evidence
    KEV = "kev"  # KEV listing changed


@dataclass(frozen=True)
class Change:
    device: str
    rule: str
    kind: ChangeKind
    before: str | None
    after: str | None
    detail: str = ""

    def __str__(self) -> str:
        arrow = f"{self.before or '-'} -> {self.after or '-'}"
        extra = f" ({self.detail})" if self.detail else ""
        return f"{self.kind.value:<8} {self.device} {self.rule}: {arrow}{extra}"


def snapshot(results: Sequence[CheckResult], taken: str) -> dict[str, Any]:
    entries = {}
    for item in results:
        r = item.result
        entries[f"{item.device.name}/{r.rule_id}"] = {
            "verdict": r.verdict.value,
            "exposure": r.exposure.value if r.exposure else None,
            "mitigation": r.mitigation,
            "evidence": sorted({e.text for e in r.evidence}),
            "kev": sorted(k.cve for k in item.kev),
        }
    return {"version": SNAPSHOT_VERSION, "taken": taken, "results": dict(sorted(entries.items()))}


def load_snapshot(path: Path) -> dict[str, Any] | None:
    """The saved snapshot, or None if the state file does not exist yet."""
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise DriftError(f"cannot read state file {path}: {exc}") from None
    if not isinstance(data, dict) or data.get("version") != SNAPSHOT_VERSION:
        raise DriftError(f"state file {path} has an unknown format; delete it to start over")
    return data


def save_snapshot(path: Path, snap: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(snap, indent=2) + "\n", encoding="utf-8")
    tmp.chmod(0o600)  # inventory and exposure data: owner only
    tmp.replace(path)


def _split(key: str) -> tuple[str, str]:
    device, _, rule = key.partition("/")
    return device, rule


def diff(old: Mapping[str, Any], new: Mapping[str, Any]) -> list[Change]:
    """Changes from snapshot ``old`` to snapshot ``new``, sorted by device, rule, kind."""
    before: Mapping[str, Any] = old["results"]
    after: Mapping[str, Any] = new["results"]
    changes = []
    for key in sorted(before.keys() | after.keys()):
        device, rule = _split(key)
        if key not in before:
            changes.append(Change(device, rule, ChangeKind.NEW, None, after[key]["verdict"]))
            continue
        if key not in after:
            changes.append(Change(device, rule, ChangeKind.GONE, before[key]["verdict"], None))
            continue
        a, b = before[key], after[key]
        if a["verdict"] != b["verdict"]:
            detail = f"exposure {a['exposure']} -> {b['exposure']}"
            changes.append(
                Change(device, rule, ChangeKind.VERDICT, a["verdict"], b["verdict"], detail)
            )
        elif (a["exposure"], a["mitigation"], a["evidence"]) != (
            b["exposure"],
            b["mitigation"],
            b["evidence"],
        ):
            added = len(set(b["evidence"]) - set(a["evidence"]))
            removed = len(set(a["evidence"]) - set(b["evidence"]))
            detail = f"evidence +{added} -{removed}"
            changes.append(
                Change(device, rule, ChangeKind.EVIDENCE, a["verdict"], b["verdict"], detail)
            )
        if a["kev"] != b["kev"]:
            old_kev, new_kev = ",".join(a["kev"]) or None, ",".join(b["kev"]) or None
            changes.append(Change(device, rule, ChangeKind.KEV, old_kev, new_kev))
    return changes


def changes_json(changes: Sequence[Change], old_taken: str, new_taken: str) -> str:
    data = {
        "baseline": old_taken,
        "current": new_taken,
        "changes": [
            {
                "device": c.device,
                "rule": c.rule,
                "kind": c.kind.value,
                "before": c.before,
                "after": c.after,
                "detail": c.detail,
            }
            for c in changes
        ],
    }
    return json.dumps(data, indent=2)
