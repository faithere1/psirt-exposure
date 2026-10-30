"""Golden eval set: score final verdicts on held-out advisory x config pairs.

``eval/golden/cases.yaml`` lists each pair with the expected exposure and final verdict. Any rule
directory can be scored (reviewed rules or LLM drafts); a missing rule predicts ``no-rule``.
The verdicts come from the same ``run_check`` pipeline as ``check``, so the score measures the
shipped behavior. Reports are deterministic for the same input (no timestamps).
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from psirt_exposure.check import run_check
from psirt_exposure.inventory import Device
from psirt_exposure.matcher import Exposure, Verdict
from psirt_exposure.psirt import VersionSource
from psirt_exposure.rules import Rule

MISSING = "no-rule"
VERDICTS = tuple(v.value for v in Verdict)
EXPOSURES = tuple(e.value for e in Exposure)


class GoldenError(ValueError):
    """The cases file is malformed."""


@dataclass(frozen=True)
class GoldenCase:
    device: str
    rule: str
    exposure: str | None
    verdict: str
    note: str = ""

    @property
    def id(self) -> str:
        return f"{self.device}/{self.rule}"


@dataclass(frozen=True)
class Scored:
    case: GoldenCase
    exposure: str | None
    verdict: str

    @property
    def verdict_ok(self) -> bool:
        return self.verdict == self.case.verdict

    @property
    def exposure_ok(self) -> bool:
        return self.exposure == self.case.exposure


def load_cases(path: Path) -> tuple[Path, list[GoldenCase]]:
    """The device directory (relative to the cases file) and the cases, validated."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("cases"), list):
        raise GoldenError(f"{path}: expected a mapping with a 'cases' list")
    devices = path.parent / str(data.get("devices", "devices"))
    cases: list[GoldenCase] = []
    seen: set[str] = set()
    for i, raw in enumerate(data["cases"], 1):
        try:
            case = GoldenCase(
                device=str(raw["device"]),
                rule=str(raw["rule"]),
                exposure=raw["exposure"],
                verdict=str(raw["verdict"]),
                note=str(raw.get("note", "")),
            )
        except (KeyError, TypeError) as exc:
            raise GoldenError(f"{path}: case {i} is missing {exc}") from None
        if case.verdict not in VERDICTS:
            raise GoldenError(f"{path}: {case.id}: unknown verdict {case.verdict!r}")
        if case.exposure is not None and case.exposure not in EXPOSURES:
            raise GoldenError(f"{path}: {case.id}: unknown exposure {case.exposure!r}")
        if case.id in seen:
            raise GoldenError(f"{path}: duplicate case {case.id}")
        seen.add(case.id)
        cases.append(case)
    return devices, cases


def score_cases(
    cases: Sequence[GoldenCase],
    devices: Mapping[str, Device],
    rules: Mapping[str, Rule],
    versions: VersionSource | None,
) -> list[Scored]:
    missing = sorted({c.device for c in cases} - devices.keys())
    if missing:
        raise GoldenError(f"devices not found: {', '.join(missing)}")
    out = []
    for case in cases:
        rule = rules.get(case.rule)
        if rule is None:
            out.append(Scored(case, MISSING, MISSING))
            continue
        result = run_check([devices[case.device]], [rule], versions)[0].result
        exposure = result.exposure.value if result.exposure else None
        out.append(Scored(case, exposure, result.verdict.value))
    return out


def _ratio(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def metrics(scored: Sequence[Scored]) -> dict[str, Any]:
    """Accuracy, per-verdict precision/recall/F1, AFFECTED detection, confusion matrix."""
    n = len(scored)
    per_verdict: dict[str, dict[str, Any]] = {}
    for v in VERDICTS:
        tp = sum(s.case.verdict == v and s.verdict == v for s in scored)
        fp = sum(s.case.verdict != v and s.verdict == v for s in scored)
        fn = sum(s.case.verdict == v and s.verdict != v for s in scored)
        p, r = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
        f1 = None if p is None or r is None else round(2 * p * r / (p + r), 4) if p + r else 0.0
        per_verdict[v] = {
            "support": tp + fn,
            "predicted": tp + fp,
            "precision": p,
            "recall": r,
            "f1": f1,
        }
    affected = per_verdict[Verdict.AFFECTED.value]
    per_rule: dict[str, dict[str, int]] = {}
    for s in scored:
        row = per_rule.setdefault(s.case.rule, {"cases": 0, "correct": 0})
        row["cases"] += 1
        row["correct"] += s.verdict_ok
    confusion = Counter((s.case.verdict, s.verdict) for s in scored)
    return {
        "cases": n,
        "devices": len({s.case.device for s in scored}),
        "rules": len(per_rule),
        "verdict_correct": sum(s.verdict_ok for s in scored),
        "verdict_accuracy": _ratio(sum(s.verdict_ok for s in scored), n),
        "exposure_correct": sum(s.exposure_ok for s in scored),
        "exposure_accuracy": _ratio(sum(s.exposure_ok for s in scored), n),
        "affected_precision": affected["precision"],
        "affected_recall": affected["recall"],
        "per_verdict": per_verdict,
        "per_rule": dict(sorted(per_rule.items())),
        "confusion": [
            {"expected": e, "predicted": p, "count": c} for (e, p), c in sorted(confusion.items())
        ],
    }


def fmt_ratio(value: float | None) -> str:
    return "-" if value is None else f"{value:.2f}"


def report_markdown(scored: Sequence[Scored], meta: Mapping[str, str]) -> str:
    m = metrics(scored)
    lines = ["# Golden eval report", ""]
    lines += [f"- {k}: `{v}`" for k, v in meta.items()]
    lines += [
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Cases (advisory x config pairs) | {m['cases']} ({m['devices']} devices, "
        f"{m['rules']} rules) |",
        f"| Verdict accuracy | {m['verdict_correct']}/{m['cases']} "
        f"({fmt_ratio(m['verdict_accuracy'])}) |",
        f"| Exposure accuracy | {m['exposure_correct']}/{m['cases']} "
        f"({fmt_ratio(m['exposure_accuracy'])}) |",
        f"| AFFECTED precision | {fmt_ratio(m['affected_precision'])} |",
        f"| AFFECTED recall | {fmt_ratio(m['affected_recall'])} |",
        "",
        "## Per verdict",
        "",
        "| Verdict | Support | Predicted | Precision | Recall | F1 |",
        "|---|---|---|---|---|---|",
    ]
    for v, row in m["per_verdict"].items():
        lines.append(
            f"| {v} | {row['support']} | {row['predicted']} | {fmt_ratio(row['precision'])} | "
            f"{fmt_ratio(row['recall'])} | {fmt_ratio(row['f1'])} |"
        )
    lines += ["", "## Per rule", "", "| Rule | Correct |", "|---|---|"]
    lines += [f"| {k} | {r['correct']}/{r['cases']} |" for k, r in m["per_rule"].items()]
    lines += ["", "## Confusion (expected -> predicted)", "", "| Expected | Predicted | Count |"]
    lines.append("|---|---|---|")
    lines += [f"| {c['expected']} | {c['predicted']} | {c['count']} |" for c in m["confusion"]]
    wrong = [s for s in scored if not (s.verdict_ok and s.exposure_ok)]
    lines += ["", "## Mismatches", ""]
    if not wrong:
        lines.append("None.")
    else:
        lines += ["| Case | Expected | Predicted | Note |", "|---|---|---|---|"]
        for s in wrong:
            lines.append(
                f"| {s.case.id} | {s.case.verdict} ({s.case.exposure}) | "
                f"{s.verdict} ({s.exposure}) | {s.case.note} |"
            )
    return "\n".join(lines) + "\n"


def report_json(scored: Sequence[Scored], meta: Mapping[str, str]) -> str:
    data = {
        "meta": dict(meta),
        "metrics": metrics(scored),
        "cases": [
            {
                "id": s.case.id,
                "expected": {"exposure": s.case.exposure, "verdict": s.case.verdict},
                "predicted": {"exposure": s.exposure, "verdict": s.verdict},
                "correct": s.verdict_ok and s.exposure_ok,
            }
            for s in scored
        ],
    }
    return json.dumps(data, indent=2) + "\n"
