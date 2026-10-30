"""CLI: netsec-check check (offline sources; live lookups are stubbed or refused)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netsec_check.cli import main

ROOT = Path(__file__).resolve().parent.parent
KEV_FILE = ROOT / "tests/fixtures/kev/known_exploited_vulnerabilities.json"
BASE = [
    "check",
    "--offline",
    "--configs",
    str(ROOT / "samples/configs"),
    "--rules",
    str(ROOT / "rules"),
]


def test_table(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([*BASE, "--device", "edge-rtr-02", "--evidence"]) == 0
    out = capsys.readouterr().out.splitlines()
    header = ["DEVICE", "PLATFORM", "VERSION", "RULE", "EXPOSURE", "VERDICT", "KEV"]
    assert out[0].split() == header
    rows = [line.split() for line in out if line.startswith("edge-rtr-02")]
    assert len(rows) == 10
    verdicts = {r[3]: r[5] for r in rows}
    assert verdicts["snmp"] == "MITIGATED"
    # 17.6.5: listed as affected by the IKEv1 advisory; newer than every L2TP-affected train.
    assert verdicts["ikev1"] == "AFFECTED"
    assert verdicts["l2tp"] == "FIXED_VERSION"
    assert verdicts["webui"] == "NOT_AFFECTED_FEATURE_DISABLED"
    assert {r[6] for r in rows} == {"-"}  # no KEV data offline by default
    assert any("reason:" in line for line in out)


def test_versions_none_is_indeterminate(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([*BASE, "--versions", "none", "--device", "edge-rtr-02", "--rule", "ikev1"]) == 0
    row = capsys.readouterr().out.splitlines()[1].split()
    assert row[5] == "INDETERMINATE"


def test_unevaluated_train_is_indeterminate(capsys: pytest.CaptureFixture[str]) -> None:
    # access-sw-01 runs 16.3.7; the SNMP advisory does not evaluate the 16.3 train.
    assert main([*BASE, "--device", "access-sw-01", "--rule", "snmp", "--format", "json"]) == 0
    [item] = json.loads(capsys.readouterr().out)
    assert item["exposure"] == "present"
    assert item["verdict"] == "INDETERMINATE"


def test_offline_verdict_totals(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([*BASE, "--format", "json"]) == 0
    items = json.loads(capsys.readouterr().out)
    counts: dict[str, int] = {}
    for item in items:
        counts[item["verdict"]] = counts.get(item["verdict"], 0) + 1
    assert len(items) == 80
    assert counts["NOT_AFFECTED_FEATURE_DISABLED"] == 58
    assert counts["MITIGATED"] == 4


def test_kev_file(capsys: pytest.CaptureFixture[str]) -> None:
    args = [*BASE, "--kev", str(KEV_FILE), "--device", "branch-isr-01"]
    assert main([*args, "--rule", "webui", "--format", "json"]) == 0
    [item] = json.loads(capsys.readouterr().out)
    assert item["verdict"] == "AFFECTED"
    assert [k["cve"] for k in item["kev"]] == ["CVE-2023-20198"]
    assert main([*args, "--rule", "webui", "--rule", "iox", "--evidence"]) == 0
    out = capsys.readouterr().out
    assert "KEV: CVE-2023-20198 added 2023-10-16" in out
    rows = {line.split()[3]: line.split()[6] for line in out.splitlines()[1:] if line[0] != " "}
    assert rows == {"webui": "yes", "iox": "-"}


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["--versions", "openvuln"], "needs the network"),
        (["--kev", "cisa"], "needs the network"),
        (["--kev", "/nonexistent/kev.json"], "not found"),
        (["--advisories", "/nonexistent"], "not found"),
    ],
)
def test_offline_setup_errors(
    extra: list[str], message: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([*BASE, *extra]) == 2
    assert message in capsys.readouterr().err


def test_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([*BASE, "--device", "branch-isr-01", "--rule", "iox", "--format", "json"]) == 0
    [item] = json.loads(capsys.readouterr().out)
    assert item["exposure"] == "present"
    assert item["platform"] == "C1111-8P"
    assert {e["text"] for e in item["evidence"]} >= {"iox", "ip http secure-server"}
    assert item["runtime_checks"][0]["command"] == "show iox-service"


def test_live_needs_credentials(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("CISCO_CLIENT_ID", raising=False)
    monkeypatch.delenv("CISCO_CLIENT_SECRET", raising=False)
    args = ["check", "--configs", str(ROOT / "samples/configs"), "--rules", str(ROOT / "rules")]
    assert main([*args, "--env-file", str(tmp_path / ".env")]) == 2
    err = capsys.readouterr().err
    assert "CISCO_CLIENT_ID" in err and "--offline" in err


def test_unknown_device() -> None:
    with pytest.raises(SystemExit, match="unknown device: nope"):
        main([*BASE, "--device", "nope"])
