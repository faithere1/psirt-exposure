"""Schema validation for the rule DSL and the hand-written rules in rules/."""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from netsec_check.rules import Rule, RuleLoadError, load_rule, load_rules, rule_json_schema
from netsec_check.rules.model import (
    Block,
    Each,
    Line,
    Platform,
    VlanCoverageCond,
    children,
    fill_placeholders,
)

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
SCHEMA_FILE = RULES_DIR / "rule.schema.json"
MANIFEST = yaml.safe_load((ROOT / "tests/fixtures/psirt/manifest.yaml").read_text("utf-8"))
ADVISORIES: dict[str, dict[str, Any]] = {a["key"]: a for a in MANIFEST["advisories"]}
RULES = load_rules(RULES_DIR)

MINIMAL: dict[str, Any] = {
    "id": "example",
    "advisory_id": "cisco-sa-example-AbCd1234",
    "cves": ["CVE-2026-0001"],
    "title": "Example",
    "status": "draft",
    "summary": "Example feature is enabled.",
    "exposure": {"line": {"pattern": "^example enable$"}},
}


def _rule(**overrides: Any) -> dict[str, Any]:
    data = copy.deepcopy(MINIMAL)
    data.update(overrides)
    return data


def _walk(cond: Any) -> list[Any]:
    out = [cond]
    for child in children(cond):
        out += _walk(child)
    if isinstance(cond, Block) and cond.block.where is not None:
        out += _walk(cond.block.where)
    if isinstance(cond, Each):
        out += _walk(cond.each.require)
    return out


# --- hand-written rules ----------------------------------------------------------------------


def test_one_rule_per_manifest_advisory() -> None:
    assert set(RULES) == set(ADVISORIES)


@pytest.mark.parametrize("key", sorted(ADVISORIES))
def test_rule_matches_manifest(key: str) -> None:
    rule = RULES[key]
    adv = ADVISORIES[key]
    assert rule.advisory_id == adv["id"]
    assert sorted(rule.cves) == sorted(adv["cves"])
    assert rule.status == "reviewed"


@pytest.mark.parametrize("key", sorted(ADVISORIES))
def test_rule_title_matches_csaf(key: str) -> None:
    csaf = json.loads((ROOT / f"tests/fixtures/psirt/{ADVISORIES[key]['id']}.json").read_text())
    assert RULES[key].title == csaf["document"]["title"]


@pytest.mark.parametrize("key", sorted(ADVISORIES))
def test_rule_patterns_compile_with_bindings(key: str) -> None:
    rule = RULES[key]
    conds = [rule.exposure, *(m.condition for m in rule.mitigations)]
    for cond in conds:
        for node in _walk(cond):
            if isinstance(node, Line):
                pats = [node.line.pattern]
            elif isinstance(node, Block):
                pats = [node.block.parent, *node.block.has, *node.block.lacks]
            elif isinstance(node, Each):
                pats = [node.each.select, node.each.capture]
            elif isinstance(node, Platform):
                pats = node.platform
            elif isinstance(node, VlanCoverageCond):
                pats = [node.vlan_coverage.pattern]
            else:
                continue
            for p in pats:
                re.compile(fill_placeholders(p, _AnyValue()))


class _AnyValue(dict[str, str]):
    def __missing__(self, key: str) -> str:
        return "VALUE.with+regex*chars"


def test_rule_round_trips_through_json() -> None:
    for rule in RULES.values():
        dumped = rule.model_dump(mode="json", by_alias=True, exclude_defaults=True)
        assert Rule.model_validate(dumped) == rule


def test_committed_json_schema_is_current() -> None:
    committed = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
    hint = "regenerate: PYTHONPATH=src uv run python -m netsec_check.rules"
    assert committed == rule_json_schema(), hint


# --- schema rejects bad rules ----------------------------------------------------------------


def test_minimal_rule_is_valid() -> None:
    rule = Rule.model_validate(MINIMAL)
    assert rule.affected_platforms is None
    assert rule.mitigations == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"status": "approved"},
        {"id": "Bad_Key"},
        {"advisory_id": "not-an-advisory"},
        {"cves": []},
        {"cves": ["CVE-26-1"]},
        {"os": "nx-os"},
        {"affected_platforms": []},
        {"affected_platforms": ["^C8(300"]},
        {"unknown_field": 1},
        {"schema_version": 2},
    ],
    ids=lambda o: next(iter(o)),
)
def test_bad_top_level_fields_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Rule.model_validate(_rule(**overrides))


@pytest.mark.parametrize(
    "exposure",
    [
        {},
        {"line": {"pattern": "^a$"}, "not": {"line": {"pattern": "^b$"}}},
        {"regex": "^a$"},
        "ip http server",
        {"line": {"pattern": ""}},
        {"line": {"pattern": "^ip http (server"}},
        {"line": {"pattern": "^a$", "parent": "^b"}},
        {"all_of": []},
        {"any_of": [{"line": {"pattern": "^a$"}}, {"bogus": 1}]},
        {"block": {"parent": "^interface ", "has": ["^cip enable("]}},
        {"platform": []},
        {"platform": ["^{pid}"]},
        {"vlan_coverage": {"pattern": r"^ip dhcp snooping vlan (\S+)$", "coverage": "partial"}},
        {"vlan_coverage": {"pattern": "^x (?P<vlans>.+)$", "coverage": "some"}},
    ],
)
def test_bad_conditions_rejected(exposure: Any) -> None:
    with pytest.raises(ValidationError):
        Rule.model_validate(_rule(exposure=exposure))


@pytest.mark.parametrize(
    "exposure",
    [
        {"line": {"pattern": "^crypto map {map}$"}},
        {"block": {"parent": "^interface ", "has": ["^crypto map {map}$"]}},
        {
            "block": {
                "parent": r"^crypto map (?P<map>\S+)",
                "where": {"line": {"pattern": "^x {profile}$"}},
            }
        },
        {
            "each": {
                "select": "^snmp-server community ",
                "capture": r"view (?P<view>\S+)",
                "require": {"line": {"pattern": "^snmp-server view {name} x$"}},
            }
        },
    ],
)
def test_unbound_placeholders_rejected(exposure: Any) -> None:
    with pytest.raises(ValidationError, match="unbound placeholders"):
        Rule.model_validate(_rule(exposure=exposure))


def test_placeholders_bound_by_parent_and_capture_accepted() -> None:
    exposure = {
        "block": {
            "parent": r"^crypto map (?P<map>\S+) \d+ ipsec-isakmp$",
            "lacks": ["^set ikev2-profile "],
            "where": {
                "each": {
                    "select": "^interface ",
                    "capture": r"^interface (?P<intf>\S+)$",
                    "require": {"line": {"pattern": "^x {map} {intf}$"}},
                }
            },
        }
    }
    Rule.model_validate(_rule(exposure=exposure))


def test_not_alias_and_mitigation_ids() -> None:
    mitigation = {"id": "m-1", "description": "d", "condition": {"not": {"line": {"pattern": "a"}}}}
    Rule.model_validate(_rule(mitigations=[mitigation]))
    with pytest.raises(ValidationError, match="unique"):
        Rule.model_validate(_rule(mitigations=[mitigation, mitigation]))
    with pytest.raises(ValidationError):
        Rule.model_validate(_rule(mitigations=[{**mitigation, "id": "Bad Id"}]))


def test_fill_placeholders_escapes_values() -> None:
    pat = fill_placeholders("^crypto map {map}$", {"map": "A.B+C"})
    assert re.search(pat, "crypto map A.B+C")
    assert not re.search(pat, "crypto map AxBBC")


# --- loader ----------------------------------------------------------------------------------


def test_loader_requires_file_name_to_match_id(tmp_path: Path) -> None:
    path = tmp_path / "other.yaml"
    path.write_text(yaml.safe_dump(MINIMAL), encoding="utf-8")
    with pytest.raises(RuleLoadError, match="does not match file name"):
        load_rule(path)


@pytest.mark.parametrize("text", ["- a\n- b\n", "id: [unclosed\n", "id: example\n"])
def test_loader_reports_bad_files(tmp_path: Path, text: str) -> None:
    path = tmp_path / "example.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(RuleLoadError, match="example.yaml"):
        load_rule(path)
