"""Compare LLM-extracted draft rules with the hand-written rules and the ground-truth labels.

Both rule sets run through the same deterministic ``config_exposure`` on every sample device, so
the score measures what matters: does the draft rule give the right config-level label?
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import yaml

from psirt_exposure.inventory import Device
from psirt_exposure.matcher import Exposure, MissingFactsError, config_exposure
from psirt_exposure.rules import Rule

ERROR = "error"
MISSING = "no-rule"


def load_labels(path: Path) -> dict[str, dict[str, str]]:
    """``labels.yaml`` as ``{device: {rule key: label}}``."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return {name: dict(dev["labels"]) for name, dev in data["devices"].items()}


def _exposure(rule: Rule | None, device: Device) -> str:
    if rule is None:
        return MISSING
    try:
        return config_exposure(rule, device.config, device.facts)[0].value
    except MissingFactsError:
        return ERROR


@dataclass(frozen=True)
class Cell:
    device: str
    label: str
    hand: str
    draft: str


@dataclass(frozen=True)
class RuleScore:
    key: str
    valid: bool
    attempts: int | None
    cells: tuple[Cell, ...]

    @property
    def correct(self) -> int:
        return sum(c.draft == c.label for c in self.cells)

    @property
    def agree_hand(self) -> int:
        return sum(c.draft == c.hand for c in self.cells)

    @property
    def positives(self) -> tuple[Cell, ...]:
        return tuple(c for c in self.cells if c.label != Exposure.ABSENT)

    @property
    def exact(self) -> bool:
        return self.valid and self.correct == len(self.cells)


def score(
    keys: Sequence[str],
    hand: Mapping[str, Rule],
    drafts: Mapping[str, Rule | None],
    devices: Sequence[Device],
    labels: Mapping[str, Mapping[str, str]],
    attempts: Mapping[str, int] | None = None,
) -> list[RuleScore]:
    scores = []
    for key in keys:
        draft = drafts.get(key)
        cells = tuple(
            Cell(
                device=d.name,
                label=labels[d.name][key],
                hand=_exposure(hand.get(key), d),
                draft=_exposure(draft, d),
            )
            for d in devices
        )
        scores.append(
            RuleScore(
                key=key,
                valid=draft is not None,
                attempts=(attempts or {}).get(key),
                cells=cells,
            )
        )
    return scores


def _pct(n: int, d: int) -> str:
    return f"{n}/{d} ({100 * n / d:.0f}%)" if d else "0/0"


def summary(scores: Sequence[RuleScore]) -> dict[str, int]:
    cells = [c for s in scores for c in s.cells]
    positives = [c for s in scores for c in s.positives]
    return {
        "rules": len(scores),
        "valid": sum(s.valid for s in scores),
        "exact_rules": sum(s.exact for s in scores),
        "cells": len(cells),
        "draft_correct": sum(c.draft == c.label for c in cells),
        "hand_correct": sum(c.hand == c.label for c in cells),
        "draft_agrees_hand": sum(c.draft == c.hand for c in cells),
        "positive_cells": len(positives),
        "draft_positive_correct": sum(c.draft == c.label for c in positives),
        "baseline_always_absent": sum(c.label == Exposure.ABSENT for c in cells),
    }


def report_markdown(scores: Sequence[RuleScore], meta: Mapping[str, str]) -> str:
    s = summary(scores)
    cells, pos = s["cells"], s["positive_cells"]
    out = ["# LLM rule extraction: accuracy report", ""]
    out += [f"- {k}: `{v}`" for k, v in meta.items()]
    out += [
        "",
        "Each draft rule is run through the deterministic matcher on every sample device and the",
        "config-level result is compared with `samples/configs/labels.yaml`. The hand-written",
        "rules in `rules/` are scored the same way as a reference.",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Schema-valid draft rules | {_pct(s['valid'], s['rules'])} |",
        f"| Rules correct on every device | {_pct(s['exact_rules'], s['rules'])} |",
        f"| Draft device×advisory accuracy | {_pct(s['draft_correct'], cells)} |",
        f"| Draft accuracy on non-`absent` labels | {_pct(s['draft_positive_correct'], pos)} |",
        f"| Draft agrees with hand rule | {_pct(s['draft_agrees_hand'], cells)} |",
        f"| Hand rule accuracy (reference) | {_pct(s['hand_correct'], cells)} |",
        f"| Baseline: always `absent` | {_pct(s['baseline_always_absent'], cells)} |",
        "",
        "## Per advisory",
        "",
        "| Advisory | Valid | Attempts | Correct | Non-absent correct | Agrees with hand |",
        "|---|---|---|---|---|---|",
    ]
    for r in scores:
        n = len(r.cells)
        pos_ok = sum(c.draft == c.label for c in r.positives)
        out.append(
            f"| {r.key} | {'yes' if r.valid else 'no'} | {r.attempts or '-'} | "
            f"{_pct(r.correct, n)} | {_pct(pos_ok, len(r.positives))} | {_pct(r.agree_hand, n)} |"
        )
    misses = [(r.key, c) for r in scores for c in r.cells if c.draft != c.label]
    out += ["", "## Mismatches", ""]
    if misses:
        out += ["| Advisory | Device | Label | Draft | Hand |", "|---|---|---|---|---|"]
        out += [f"| {k} | {c.device} | {c.label} | {c.draft} | {c.hand} |" for k, c in misses]
    else:
        out.append("None.")
    return "\n".join(out) + "\n"


def report_json(scores: Sequence[RuleScore], meta: Mapping[str, str]) -> str:
    data = {
        "meta": dict(meta),
        "summary": summary(scores),
        "rules": [
            {
                "key": r.key,
                "valid": r.valid,
                "attempts": r.attempts,
                "cells": [c.__dict__ for c in r.cells],
            }
            for r in scores
        ],
    }
    return json.dumps(data, indent=2) + "\n"
