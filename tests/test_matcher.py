"""Deterministic matcher: condition kinds, per-rule positive/negative cases and sample labels."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import TypeAdapter

from netsec_check.config import DeviceConfig, DeviceFacts, parse_config
from netsec_check.inventory import load_devices
from netsec_check.matcher import (
    Evidence,
    Exposure,
    Verdict,
    check_rule,
    config_exposure,
    evaluate,
    parse_vlan_list,
)
from netsec_check.redact import redact
from netsec_check.rules import Condition, load_rules

ROOT = Path(__file__).resolve().parent.parent
RULES = load_rules(ROOT / "rules")
SAMPLES = ROOT / "samples/configs"
LABELS = yaml.safe_load((SAMPLES / "labels.yaml").read_text("utf-8"))["devices"]
DEVICES = {d.name: d for d in load_devices(SAMPLES)}

COND = TypeAdapter(Condition)


def cfg(text: str) -> DeviceConfig:
    return parse_config(text)


def facts(pid: str) -> DeviceFacts:
    return DeviceFacts(pid=pid, version="17.09.04a")


def holds(cond: dict[str, Any], text: str, pid: str | None = None) -> bool:
    return evaluate(COND.validate_python(cond), cfg(text), facts(pid) if pid else None).holds


# --- condition kinds -------------------------------------------------------------------------


def test_line_is_global_only() -> None:
    text = "interface Gi1\n ip http server\n"
    assert not holds({"line": {"pattern": "^ip http server$"}}, text)
    assert holds({"line": {"pattern": "^ip http server$"}}, "ip http server\n")


def test_block_has_lacks_where_and_bindings() -> None:
    text = """\
crypto map M1 10 ipsec-isakmp
 set peer 192.0.2.9
crypto map M2 10 ipsec-isakmp
 set ikev2-profile P
interface Gi1
 crypto map M2
"""
    applied = {"block": {"parent": "^interface ", "has": ["^crypto map {map}$"]}}
    v1 = {
        "block": {"parent": r"^crypto map (?P<map>\S+) \d+", "lacks": ["ikev2"], "where": applied}
    }
    v2 = {"block": {"parent": r"^crypto map (?P<map>\S+) \d+", "has": ["ikev2"], "where": applied}}
    assert not holds(v1, text)  # M1 has no IKEv2 profile but is not applied
    assert holds(v2, text)
    outcome = evaluate(COND.validate_python(v2), cfg(text))
    assert [e.line for e in outcome.evidence] == [3, 4, 5, 6]


def test_block_matches_nested_descendants() -> None:
    text = "vpdn-group G\n accept-dialin\n  protocol l2tp\n"
    assert holds({"block": {"parent": "^vpdn-group ", "has": ["^protocol l2tp$"]}}, text)


def test_each() -> None:
    cond = {
        "each": {
            "select": "^snmp-server community ",
            "capture": r"\sview (?P<v>\S+)",
            "require": {"line": {"pattern": "^snmp-server view {v} X excluded$"}},
        }
    }
    assert holds(cond, "hostname r\n")  # vacuous truth
    ok = "snmp-server view V X excluded\nsnmp-server community c1 view V RO\n"
    assert holds(cond, ok)
    assert not holds(cond, ok + "snmp-server community c2 RO\n")  # no view
    assert not holds(cond, "snmp-server community c1 view W RO\n")  # view lacks exclusion
    broken = evaluate(COND.validate_python(cond), cfg(ok + "snmp-server community c2 RO\n"))
    assert [e.text for e in broken.evidence] == ["snmp-server community <redacted> RO"]


def test_not_any_all() -> None:
    assert holds({"not": {"line": {"pattern": "^x$"}}}, "y\n")
    assert holds({"any_of": [{"line": {"pattern": "^x$"}}, {"line": {"pattern": "^y$"}}]}, "y\n")
    assert not holds(
        {"all_of": [{"line": {"pattern": "^x$"}}, {"line": {"pattern": "^y$"}}]}, "y\n"
    )


def test_platform_needs_facts() -> None:
    cond = {"platform": ["^C83"]}
    assert holds(cond, "", pid="C8300-1N1S-6T")
    assert not holds(cond, "", pid="C8000V")
    rule = RULES["smart-install"]
    result = check_rule(rule, cfg("hostname sw\n"), None)
    assert result.verdict is Verdict.INDETERMINATE
    assert result.exposure is None
    assert "show version" in result.reason


@pytest.mark.parametrize(
    ("snooped", "vlans", "coverage", "expected"),
    [
        ("10,20", "10 20 30", "partial", True),
        ("1,10-30", "10 20 30", "partial", False),
        ("1,10-30", "10 20 30", "all", True),
        ("40", "10", "none", True),
        ("10", "10", "none", False),
    ],
)
def test_vlan_coverage(snooped: str, vlans: str, coverage: str, expected: bool) -> None:
    text = f"ip dhcp snooping vlan {snooped}\n" + "".join(f"vlan {v}\n" for v in vlans.split())
    cond = {
        "vlan_coverage": {
            "pattern": r"^ip dhcp snooping vlan (?P<vlans>[\d,-]+)$",
            "coverage": coverage,
        }
    }
    assert holds(cond, text) is expected


def test_parse_vlan_list() -> None:
    assert parse_vlan_list("10,20-22,") == {10, 20, 21, 22}


# --- per-rule positive / negative cases ------------------------------------------------------

NAT = "interface Gi0/0/0\n ip nat outside\ninterface Gi0/0/1\n ip nat inside\n"
CMAP = (
    "crypto map CM 10 ipsec-isakmp\n set peer 192.0.2.5\n{extra}interface Gi0/0/0\n crypto map CM\n"
)
VTI = (
    "crypto ipsec profile PR\n set transform-set TS\n{extra}"
    "interface Tunnel1\n tunnel protection ipsec profile PR\n"
)
SNMP_VIEW = "snmp-server view SAFE cafSessionMethodsInfoEntry excluded\n"

# (rule, config, pid, expected exposure)
CASES: list[tuple[str, str, str, Exposure]] = [
    ("webui", "ip http server\n", "C8000V", Exposure.PRESENT),
    ("webui", "ip http secure-server\n", "C8000V", Exposure.PRESENT),
    ("webui", "no ip http server\nno ip http secure-server\n", "C8000V", Exposure.ABSENT),
    (
        "webui",
        "ip http server\nip http active-session-modules none\n",
        "C8000V",
        Exposure.MITIGATED,
    ),
    (
        "webui",
        "ip http server\nip http secure-server\nip http active-session-modules none\n",
        "C8000V",
        Exposure.PRESENT,
    ),
    ("smart-install", "hostname sw\n", "WS-C3850-24T", Exposure.PRESENT),
    ("smart-install", "no vstack\n", "WS-C3850-24T", Exposure.ABSENT),
    ("smart-install", "hostname rtr\n", "C8300-1N1S-6T", Exposure.ABSENT),
    ("snmp", "snmp-server community example-ro RO\n", "C8000V", Exposure.PRESENT),
    ("snmp", "snmp-server group G v3 priv\n", "C8000V", Exposure.ABSENT),
    (
        "snmp",
        "snmp-server group G v3 priv\nsnmp-server user u G v3 auth sha x priv aes 128 y\n",
        "C8000V",
        Exposure.PRESENT,
    ),
    (
        "snmp",
        SNMP_VIEW + "snmp-server community example-ro view SAFE RO\n",
        "C8000V",
        Exposure.MITIGATED,
    ),
    (
        "snmp",
        SNMP_VIEW + "snmp-server community example-ro view SAFE RO\n"
        "snmp-server group G v3 priv\nsnmp-server user u G v3 auth sha x priv aes 128 y\n",
        "C8000V",
        Exposure.PRESENT,
    ),
    ("cip", "interface Vlan1\n cip enable\n", "IE-3400-8P2S", Exposure.PRESENT),
    ("cip", "cip security password 0 example\n", "IE-3400-8P2S", Exposure.ABSENT),
    ("ikev1", CMAP.format(extra=""), "C8300-1N1S-6T", Exposure.PRESENT),
    ("ikev1", CMAP.format(extra=""), "C8000V", Exposure.NOT_APPLICABLE_PLATFORM),
    ("ikev1", CMAP.format(extra=" set ikev2-profile P\n"), "C8300-1N1S-6T", Exposure.ABSENT),
    ("ikev1", VTI.format(extra=""), "ISR4451-X/K9", Exposure.PRESENT),
    ("ikev1", "crypto map CM 10 ipsec-isakmp\n set peer 192.0.2.5\n", "C1111-8P", Exposure.ABSENT),
    ("ikev2", CMAP.format(extra=" set ikev2-profile P\n"), "C8000V", Exposure.PRESENT),
    ("ikev2", VTI.format(extra=" set ikev2-profile P\n"), "C8000V", Exposure.PRESENT),
    ("ikev2", VTI.format(extra=""), "C8000V", Exposure.ABSENT),
    ("iox", "iox\nip http secure-server\n", "IE-3400-8P2S", Exposure.PRESENT),
    ("iox", "iox\nno ip http server\n", "IE-3400-8P2S", Exposure.ABSENT),
    ("iox", "ip http server\n", "IE-3400-8P2S", Exposure.ABSENT),
    (
        "l2tp",
        "interface Gi0/0/2\n xconnect 192.0.2.7 100 encapsulation l2tpv3 pw-class X\n",
        "ISR4451-X/K9",
        Exposure.PRESENT,
    ),
    (
        "l2tp",
        "pseudowire-class PW\n encapsulation l2tpv3\n"
        "interface Gi0/0/2\n xconnect 192.0.2.7 100 pw-class PW\n",
        "C1111-8P",
        Exposure.PRESENT,
    ),
    (
        "l2tp",
        "pseudowire-class PW\n encapsulation mpls\n"
        "interface Gi0/0/2\n xconnect 192.0.2.7 100 pw-class PW\n",
        "C1111-8P",
        Exposure.ABSENT,
    ),
    ("l2tp", "vpdn-group G\n accept-dialin\n  protocol l2tp\n", "C8000V", Exposure.ABSENT),
    (
        "l2tp",
        "vpdn enable\nvpdn-group G\n accept-dialin\n  protocol l2tp\n",
        "C8000V",
        Exposure.PRESENT,
    ),
    (
        "l2tp",
        "vpdn enable\nvpdn-group G\n accept-dialin\n  protocol l2tp\n",
        "C9300-24T",
        Exposure.NOT_APPLICABLE_PLATFORM,
    ),
    ("nat-dns-alg", NAT, "C8000V", Exposure.PRESENT),
    (
        "nat-dns-alg",
        "ip nat inside source list 1 interface Gi0/0/0 overload\n",
        "C8000V",
        Exposure.ABSENT,
    ),
    (
        "nat-dns-alg",
        NAT + "no ip nat service dns tcp\nno ip nat service dns udp\n",
        "C8000V",
        Exposure.MITIGATED,
    ),
    ("nat-dns-alg", NAT + "no ip nat service dns tcp\n", "C8000V", Exposure.PRESENT),
    (
        "dhcp-snooping",
        "ip dhcp snooping vlan 10\nip dhcp snooping\nvlan 10\n",
        "C8300-1N1S-6T",
        Exposure.PRESENT,
    ),
    (
        "dhcp-snooping",
        "ip dhcp snooping vlan 1,10\nip dhcp snooping\nvlan 10\n",
        "C8300-1N1S-6T",
        Exposure.ABSENT,
    ),
    ("dhcp-snooping", "ip dhcp snooping vlan 10\nvlan 10\n", "C8300-1N1S-6T", Exposure.ABSENT),
    (
        "dhcp-snooping",
        "ip dhcp snooping vlan 10\nip dhcp snooping\nvlan 10\n",
        "C9300-24T",
        Exposure.NOT_APPLICABLE_PLATFORM,
    ),
]


@pytest.mark.parametrize(("rule_id", "text", "pid", "expected"), CASES)
def test_rule_cases(rule_id: str, text: str, pid: str, expected: Exposure) -> None:
    exposure, _, _, _ = config_exposure(RULES[rule_id], cfg(text), facts(pid))
    assert exposure is expected


def test_every_rule_has_positive_and_negative_case() -> None:
    for rule_id in RULES:
        seen = {e for r, _, _, e in CASES if r == rule_id}
        assert Exposure.PRESENT in seen, rule_id
        assert seen - {Exposure.PRESENT}, rule_id
    for rule_id, rule in RULES.items():
        seen = {e for r, _, _, e in CASES if r == rule_id}
        if rule.mitigations:
            assert Exposure.MITIGATED in seen, rule_id
        if rule.affected_platforms:
            assert Exposure.NOT_APPLICABLE_PLATFORM in seen, rule_id


# --- sample devices vs. labels.yaml ----------------------------------------------------------

LABEL_CASES = [(d, k, v) for d, info in sorted(LABELS.items()) for k, v in info["labels"].items()]


@pytest.mark.parametrize(("device", "rule_id", "label"), LABEL_CASES)
def test_verdict_table_matches_labels(device: str, rule_id: str, label: str) -> None:
    dev = DEVICES[device]
    result = check_rule(RULES[rule_id], dev.config, dev.facts)
    assert result.exposure == Exposure(label), result.reason
    if result.exposure in (Exposure.PRESENT, Exposure.MITIGATED, Exposure.NOT_APPLICABLE_PLATFORM):
        # Default-on features (Smart Install) have only the platform as evidence.
        assert result.evidence, "configured feature needs evidence"


def test_label_coverage() -> None:
    assert len(LABEL_CASES) == len(LABELS) * len(RULES)


# --- final verdicts --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "version_affected", "verdict"),
    [
        ("ip http server\n", None, Verdict.INDETERMINATE),
        ("ip http server\n", True, Verdict.AFFECTED),
        ("ip http server\n", False, Verdict.FIXED_VERSION),
        ("no ip http server\n", True, Verdict.NOT_AFFECTED_FEATURE_DISABLED),
        ("ip http server\nip http active-session-modules none\n", True, Verdict.MITIGATED),
    ],
)
def test_check_rule_verdicts(text: str, version_affected: bool | None, verdict: Verdict) -> None:
    result = check_rule(RULES["webui"], cfg(text), facts("C8000V"), version_affected)
    assert result.verdict is verdict
    assert result.advisory_id == RULES["webui"].advisory_id
    if verdict is Verdict.MITIGATED:
        assert result.mitigation == "session-modules-none"


def test_evidence_is_redacted_and_ordered() -> None:
    result = check_rule(RULES["snmp"], cfg("snmp-server community s3cr3t-example RO\n"), None)
    assert result.evidence == (Evidence(1, "snmp-server community <redacted> RO"),)


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("snmp-server community example view V RO", "snmp-server community <redacted> view V RO"),
        (
            "snmp-server user u G v3 auth sha AUTHX priv aes 128 PRIVX",
            "snmp-server user u G v3 auth sha <redacted> priv aes 128 <redacted>",
        ),
        ("enable secret 9 $9$abc", "enable secret 9 <redacted>"),
        (
            "username a privilege 15 password 0 example",
            "username a privilege 15 password 0 <redacted>",
        ),
        ("pre-shared-key local example", "pre-shared-key local <redacted>"),
        (
            "crypto isakmp key example address 192.0.2.1",
            "crypto isakmp key <redacted> address 192.0.2.1",
        ),
        ("key 7 0822455D0A16", "key 7 <redacted>"),
        ("ip http server", "ip http server"),
    ],
)
def test_redact(line: str, expected: str) -> None:
    assert redact(line) == expected
