"""Drift detection: snapshots, diffs and the watch command."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from psirt_exposure import drift
from psirt_exposure.check import run_check
from psirt_exposure.cli import main
from psirt_exposure.inventory import load_devices
from psirt_exposure.psirt import CsafVersionSource, load_kev
from psirt_exposure.rules import load_rules

ROOT = Path(__file__).resolve().parent.parent
ADVISORIES = ROOT / "tests/fixtures/psirt"
KEV_FILE = ROOT / "tests/fixtures/kev/known_exploited_vulnerabilities.json"


@pytest.fixture
def configs(tmp_path: Path) -> Path:
    target = tmp_path / "configs"
    shutil.copytree(ROOT / "samples/configs", target)
    return target


def _snap(configs: Path, kev: bool = False) -> dict[str, object]:
    results = run_check(
        load_devices(configs),
        list(load_rules(ROOT / "rules").values()),
        CsafVersionSource.from_dir(ADVISORIES),
        load_kev(KEV_FILE) if kev else None,
    )
    return drift.snapshot(results, "t")


def _edit(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def test_snapshot_shape(configs: Path) -> None:
    snap = _snap(configs)
    assert snap["version"] == drift.SNAPSHOT_VERSION
    results = snap["results"]
    assert isinstance(results, dict)
    assert len(results) == 80
    entry = results["edge-rtr-02/snmp"]
    assert entry["verdict"] == "MITIGATED"
    assert entry["mitigation"] == "exclude-affected-oid"
    assert all("line" not in e for e in entry["evidence"])  # texts only


def test_no_drift(configs: Path) -> None:
    assert drift.diff(_snap(configs), _snap(configs)) == []


def test_line_shift_is_not_drift(configs: Path) -> None:
    cfg = configs / "edge-rtr-01/running-config.txt"
    _edit(cfg, "!\n", "!\nbanner motd ^Authorized use only^\n!\n")
    before = _snap(ROOT / "samples/configs")
    assert drift.diff(before, _snap(configs)) == []


def test_config_drift_kinds(configs: Path) -> None:
    before = _snap(configs)
    # edge-rtr-02: an unrestricted community breaks the SNMP mitigation.
    cfg2 = configs / "edge-rtr-02/running-config.txt"
    cfg2.write_text(cfg2.read_text() + "snmp-server community EXAMPLEnew RO\n")
    # edge-rtr-01: one of two HTTP servers removed; still exposed, evidence shrinks.
    _edit(configs / "edge-rtr-01/running-config.txt", "\nip http server\n", "\nno ip http server\n")
    # A new device and a removed one.
    shutil.copytree(configs / "branch-isr-01", configs / "branch-isr-09")
    shutil.rmtree(configs / "ind-sw-01")
    changes = drift.diff(before, _snap(configs))
    kinds = {(c.device, c.rule): c for c in changes}
    snmp = kinds["edge-rtr-02", "snmp"]
    assert (snmp.before, snmp.after) == ("MITIGATED", "AFFECTED")
    assert snmp.kind is drift.ChangeKind.VERDICT
    assert "mitigated -> present" in snmp.detail
    webui = kinds["edge-rtr-01", "webui"]
    assert (webui.kind, webui.detail) == (drift.ChangeKind.EVIDENCE, "evidence +0 -1")
    assert kinds["branch-isr-09", "webui"].kind is drift.ChangeKind.NEW
    assert kinds["ind-sw-01", "cip"].kind is drift.ChangeKind.GONE
    assert sum(c.kind is drift.ChangeKind.NEW for c in changes) == 10
    assert str(snmp).startswith("verdict  edge-rtr-02 snmp: MITIGATED -> AFFECTED")


def test_kev_drift(configs: Path) -> None:
    changes = drift.diff(_snap(configs), _snap(configs, kev=True))
    assert changes
    assert {c.kind for c in changes} == {drift.ChangeKind.KEV}
    assert all(c.before is None and c.after for c in changes)


def test_state_file_roundtrip_and_errors(tmp_path: Path) -> None:
    path = tmp_path / "sub/state.json"
    assert drift.load_snapshot(path) is None
    snap = {"version": drift.SNAPSHOT_VERSION, "taken": "t", "results": {}}
    drift.save_snapshot(path, snap)
    assert drift.load_snapshot(path) == snap
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(drift.DriftError, match="cannot read"):
        drift.load_snapshot(path)
    path.write_text('{"version": 99}', encoding="utf-8")
    with pytest.raises(drift.DriftError, match="unknown format"):
        drift.load_snapshot(path)


def _watch(configs: Path, state: Path, *extra: str) -> list[str]:
    return ["watch", "--offline", "--configs", str(configs), "--rules", str(ROOT / "rules")] + [
        "--advisories",
        str(ADVISORIES),
        "--state",
        str(state),
        *extra,
    ]


def test_cli_watch(configs: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    state = tmp_path / "state.json"
    assert main(_watch(configs, state)) == 0
    assert "baseline saved" in capsys.readouterr().out
    assert main(_watch(configs, state)) == 0
    assert "0 change(s)" in capsys.readouterr().out
    cfg = configs / "edge-rtr-02/running-config.txt"
    cfg.write_text(cfg.read_text() + "snmp-server community EXAMPLEnew RO\n")
    assert main(_watch(configs, state, "--format", "json")) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["changes"] == [
        {
            "device": "edge-rtr-02",
            "rule": "snmp",
            "kind": "verdict",
            "before": "MITIGATED",
            "after": "AFFECTED",
            "detail": "exposure mitigated -> present",
        }
    ]
    # The state now holds the new run, so the next run is clean again.
    assert main(_watch(configs, state)) == 0
    out = capsys.readouterr().out
    assert "0 change(s)" in out
    assert "EXAMPLEnew" not in state.read_text()  # communities are redacted in evidence


def test_cli_watch_loop(
    configs: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "state.json"
    sleeps: list[float] = []
    cfg = configs / "edge-rtr-02/running-config.txt"

    def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        if len(sleeps) == 1:  # drift appears between run 1 and run 2
            cfg.write_text(cfg.read_text() + "snmp-server community EXAMPLEnew RO\n")

    monkeypatch.setattr("psirt_exposure.cli.time.sleep", fake_sleep)
    assert main(_watch(configs, state, "--interval", "30", "--count", "3")) == 1
    assert sleeps == [30, 30]
    out = capsys.readouterr().out.splitlines()
    assert "baseline saved" in out[0]
    assert "1 change(s)" in out[1]
    assert any("0 change(s)" in line for line in out[2:])


def test_cli_watch_errors(
    configs: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    state = tmp_path / "state.json"
    state.write_text("[]", encoding="utf-8")
    assert main(_watch(configs, state)) == 2
    assert "unknown format" in capsys.readouterr().err
    assert main(_watch(tmp_path / "nowhere", tmp_path / "s2.json")) == 2
    assert "not found" in capsys.readouterr().err
