"""Golden eval set: case file, held-out devices, scorer metrics and the eval-golden CLI."""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

import pytest

from psirt_exposure import golden
from psirt_exposure.cli import main
from psirt_exposure.inventory import load_devices
from psirt_exposure.psirt import CsafVersionSource
from psirt_exposure.rules import load_rules

ROOT = Path(__file__).resolve().parent.parent
CASES = ROOT / "eval/golden/cases.yaml"
RULES = ROOT / "rules"
ADVISORIES = ROOT / "tests/fixtures/psirt"
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
IPV4_RE = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
SECRET_RE = re.compile(r"\b(?:secret|key|password|community)\s+(?:\d\s+)?(\S+)")


def _score(rules_dir: Path = RULES) -> list[golden.Scored]:
    device_dir, cases = golden.load_cases(CASES)
    devices = {d.name: d for d in load_devices(device_dir)}
    versions = CsafVersionSource.from_dir(ADVISORIES)
    return golden.score_cases(cases, devices, load_rules(rules_dir), versions)


def test_case_file_shape() -> None:
    device_dir, cases = golden.load_cases(CASES)
    assert len(cases) >= 30
    devices = {d.name for d in load_devices(device_dir)}
    assert {c.device for c in cases} == devices
    assert {c.rule for c in cases} == set(load_rules(RULES))
    # Every verdict appears, so per-verdict metrics are defined.
    assert {c.verdict for c in cases} == set(golden.VERDICTS)
    # Held out: no golden device shares a name with a development sample.
    assert not devices & {d.name for d in load_devices(ROOT / "samples/configs")}


def test_golden_devices_are_sanitized() -> None:
    device_dir, _ = golden.load_cases(CASES)
    for path in sorted(device_dir.rglob("*.txt")):
        text = path.read_text(encoding="utf-8")
        for raw in IPV4_RE.findall(text):
            if raw.startswith(("255.", "0.")):
                continue
            addr = ipaddress.ip_address(raw)
            assert any(addr in net for net in DOC_NETS), f"{path}: {raw}"
        for value in SECRET_RE.findall(text):
            assert "EXAMPLE" in value, f"{path}: {value}"
        for serial in re.findall(r"Processor board ID (\S+)", text):
            assert "FAKE" in serial


def test_reviewed_rules_score_every_case() -> None:
    scored = _score()
    wrong = [s.case.id for s in scored if not (s.verdict_ok and s.exposure_ok)]
    assert wrong == []


def test_committed_report_is_current() -> None:
    """eval/golden/report.md must be regenerated after changing rules or cases."""
    meta = {"cases": "eval/golden/cases.yaml", "rules": "rules", "versions": "csaf (offline)"}
    expected = golden.report_markdown(_score(), meta)
    assert (ROOT / "eval/golden/report.md").read_text(encoding="utf-8") == expected


def test_missing_rule_predicts_no_rule(tmp_path: Path) -> None:
    (tmp_path / "webui.yaml").write_text((RULES / "webui.yaml").read_text(encoding="utf-8"))
    scored = _score(tmp_path)
    assert {s.verdict for s in scored if s.case.rule != "webui"} == {golden.MISSING}
    assert all(s.verdict_ok for s in scored if s.case.rule == "webui")


def _case(verdict: str, rule: str = "r") -> golden.GoldenCase:
    return golden.GoldenCase(device="d", rule=rule, exposure=None, verdict=verdict)


def test_metrics_math() -> None:
    a, n, i = "AFFECTED", "NOT_AFFECTED_FEATURE_DISABLED", "INDETERMINATE"
    scored = [
        golden.Scored(_case(a), None, a),  # TP
        golden.Scored(_case(a), None, n),  # FN
        golden.Scored(_case(n), None, a),  # FP
        golden.Scored(_case(n), None, n),
        golden.Scored(_case(i, "q"), None, i),
    ]
    m = golden.metrics(scored)
    assert m["cases"] == 5
    assert m["verdict_correct"] == 3
    assert m["verdict_accuracy"] == 0.6
    assert m["exposure_accuracy"] == 1.0
    assert m["affected_precision"] == 0.5
    assert m["affected_recall"] == 0.5
    assert m["per_verdict"][a]["f1"] == 0.5
    assert m["per_verdict"]["MITIGATED"] == {
        "support": 0,
        "predicted": 0,
        "precision": None,
        "recall": None,
        "f1": None,
    }
    assert m["per_rule"] == {"q": {"cases": 1, "correct": 1}, "r": {"cases": 4, "correct": 2}}
    assert {"expected": n, "predicted": a, "count": 1} in m["confusion"]


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("cases: 3\n", "'cases' list"),
        ("cases:\n  - {device: d, rule: r, exposure: null}\n", "missing"),
        ("cases:\n  - {device: d, rule: r, exposure: null, verdict: BAD}\n", "unknown verdict"),
        ("cases:\n  - {device: d, rule: r, exposure: on, verdict: AFFECTED}\n", "unknown exposure"),
        (
            "cases:\n"
            "  - {device: d, rule: r, exposure: null, verdict: AFFECTED}\n"
            "  - {device: d, rule: r, exposure: null, verdict: AFFECTED}\n",
            "duplicate",
        ),
    ],
)
def test_case_file_errors(tmp_path: Path, body: str, message: str) -> None:
    path = tmp_path / "cases.yaml"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(golden.GoldenError, match=message):
        golden.load_cases(path)


def test_cli_eval_golden(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    args = ["eval-golden", "--cases", str(CASES), "--rules", str(RULES)]
    args += ["--advisories", str(ADVISORIES), "--out", str(tmp_path)]
    assert main([*args, "--min-accuracy", "1"]) == 0
    assert "verdicts 60/60" in capsys.readouterr().out
    data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert data["metrics"]["verdict_accuracy"] == 1.0
    assert "| Verdict accuracy | 60/60 (1.00) |" in (tmp_path / "report.md").read_text()


def test_cli_eval_golden_min_accuracy(tmp_path: Path) -> None:
    (tmp_path / "rules").mkdir()
    args = ["eval-golden", "--cases", str(CASES), "--rules", str(tmp_path / "rules")]
    args += ["--advisories", str(ADVISORIES), "--out", str(tmp_path)]
    assert main([*args, "--min-accuracy", "0.5"]) == 1
    assert main(args) == 0


def test_cli_eval_golden_missing_devices(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cases = tmp_path / "cases.yaml"
    cases.write_text(
        "cases:\n  - {device: ghost, rule: webui, exposure: absent, "
        "verdict: NOT_AFFECTED_FEATURE_DISABLED}\n",
        encoding="utf-8",
    )
    (tmp_path / "devices").mkdir()
    assert main(["eval-golden", "--cases", str(cases), "--advisories", str(ADVISORIES)]) == 2
    assert "devices not found: ghost" in capsys.readouterr().err
