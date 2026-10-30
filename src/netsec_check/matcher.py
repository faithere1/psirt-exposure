"""Deterministic rule evaluation with evidence.

Every condition evaluates to an ``Outcome``: whether it holds plus the lines that support that
result (for a true ``line`` the matching lines, for a false ``each`` the lines that broke it, and
so on). The config-level verdict order is documented in ``netsec_check.rules.model``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum

from netsec_check.config import ConfigLine, DeviceConfig, DeviceFacts
from netsec_check.redact import redact
from netsec_check.rules.model import (
    AllOf,
    AnyOf,
    Block,
    Condition,
    Each,
    Line,
    Not,
    Platform,
    Rule,
    RuntimeCheck,
    VlanCoverage,
    VlanCoverageCond,
    fill_placeholders,
)

_VLAN_LINE_RE = re.compile(r"^vlan (?P<vlans>[\d,-]+)$")


class Exposure(StrEnum):
    """Config-level result; the labels in ``samples/configs/labels.yaml`` use the same values."""

    PRESENT = "present"
    ABSENT = "absent"
    MITIGATED = "mitigated"
    NOT_APPLICABLE_PLATFORM = "not_applicable_platform"


class Verdict(StrEnum):
    AFFECTED = "AFFECTED"
    NOT_AFFECTED_FEATURE_DISABLED = "NOT_AFFECTED_FEATURE_DISABLED"
    FIXED_VERSION = "FIXED_VERSION"
    MITIGATED = "MITIGATED"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True, order=True)
class Evidence:
    """A config line (``line`` is 1-based, secrets redacted) or, with ``line`` None, a
    ``show version`` fact."""

    line: int | None
    text: str

    def __str__(self) -> str:
        where = f"line {self.line}" if self.line is not None else "show version"
        return f"{where}: {self.text}"


@dataclass(frozen=True)
class Outcome:
    holds: bool
    evidence: tuple[Evidence, ...] = ()


class MissingFactsError(Exception):
    """A rule needs the device PID but no ``show version`` was supplied."""


def _ev(lines: Iterable[ConfigLine]) -> tuple[Evidence, ...]:
    return tuple(Evidence(cl.number, redact(cl.text)) for cl in lines)


def _merge(*groups: Iterable[Evidence]) -> tuple[Evidence, ...]:
    seen: set[Evidence] = set()
    for group in groups:
        seen.update(group)
    return tuple(sorted(seen, key=lambda e: (e.line is not None, e.line or 0, e.text)))


def parse_vlan_list(text: str) -> set[int]:
    """Expand ``10,20-22`` into ``{10, 20, 21, 22}``."""
    vlans: set[int] = set()
    for part in text.split(","):
        if not part:
            continue
        low, _, high = part.partition("-")
        start = int(low)
        vlans.update(range(start, int(high or start) + 1))
    return vlans


@dataclass
class _Context:
    config: DeviceConfig
    facts: DeviceFacts | None
    _cache: dict[str, re.Pattern[str]] = field(default_factory=dict)

    def regex(self, pattern: str, bindings: dict[str, str]) -> re.Pattern[str]:
        filled = fill_placeholders(pattern, bindings)
        compiled = self._cache.get(filled)
        if compiled is None:
            compiled = self._cache[filled] = re.compile(filled)
        return compiled

    def pid(self) -> str:
        if self.facts is None:
            raise MissingFactsError("rule needs the device PID from show version")
        return self.facts.pid


def _evaluate(cond: Condition, ctx: _Context, bindings: dict[str, str]) -> Outcome:
    if isinstance(cond, AllOf):
        results = [_evaluate(c, ctx, bindings) for c in cond.all_of]
        failed = [r for r in results if not r.holds]
        if failed:
            return Outcome(False, failed[0].evidence)
        return Outcome(True, _merge(*(r.evidence for r in results)))
    if isinstance(cond, AnyOf):
        results = [_evaluate(c, ctx, bindings) for c in cond.any_of]
        passed = [r for r in results if r.holds]
        return Outcome(bool(passed), _merge(*(r.evidence for r in (passed or results))))
    if isinstance(cond, Not):
        inner = _evaluate(cond.not_, ctx, bindings)
        return Outcome(not inner.holds, inner.evidence)
    if isinstance(cond, Line):
        rx = ctx.regex(cond.line.pattern, bindings)
        hits = [cl for cl in ctx.config.lines if rx.search(cl.text)]
        return Outcome(bool(hits), _ev(hits))
    if isinstance(cond, Block):
        return _block(cond, ctx, bindings)
    if isinstance(cond, Each):
        return _each(cond, ctx, bindings)
    if isinstance(cond, Platform):
        pid = ctx.pid()
        holds = any(re.search(p, pid) for p in cond.platform)
        return Outcome(holds, (Evidence(None, f"platform {pid}"),))
    if isinstance(cond, VlanCoverageCond):
        return _vlan_coverage(cond, ctx, bindings)
    raise TypeError(f"unknown condition {type(cond).__name__}")  # pragma: no cover


def _block(cond: Block, ctx: _Context, bindings: dict[str, str]) -> Outcome:
    spec = cond.block
    parent_rx = ctx.regex(spec.parent, bindings)
    evidence: list[Evidence] = []
    for top in ctx.config.lines:
        m = parent_rx.search(top.text)
        if m is None:
            continue
        inner = {**bindings, **{k: v for k, v in m.groupdict().items() if v is not None}}
        below = top.descendants()
        matched: list[ConfigLine] = []
        ok = True
        for pattern in spec.has:
            rx = ctx.regex(pattern, inner)
            hits = [cl for cl in below if rx.search(cl.text)]
            if not hits:
                ok = False
                break
            matched.extend(hits)
        if ok:
            for pattern in spec.lacks:
                rx = ctx.regex(pattern, inner)
                if any(rx.search(cl.text) for cl in below):
                    ok = False
                    break
        where_ev: tuple[Evidence, ...] = ()
        if ok and spec.where is not None:
            where = _evaluate(spec.where, ctx, inner)
            ok, where_ev = where.holds, where.evidence
        if ok:
            evidence.extend(_ev([top, *matched]))
            evidence.extend(where_ev)
    return Outcome(bool(evidence), _merge(evidence))


def _each(cond: Each, ctx: _Context, bindings: dict[str, str]) -> Outcome:
    spec = cond.each
    select_rx = ctx.regex(spec.select, bindings)
    capture_rx = ctx.regex(spec.capture, bindings)
    supporting: list[Evidence] = []
    broken: list[Evidence] = []
    for cl in ctx.config.lines:
        if not select_rx.search(cl.text):
            continue
        m = capture_rx.search(cl.text)
        if m is None:
            broken.extend(_ev([cl]))
            continue
        inner = {**bindings, **{k: v for k, v in m.groupdict().items() if v is not None}}
        result = _evaluate(spec.require, ctx, inner)
        if result.holds:
            supporting.extend(_ev([cl]))
            supporting.extend(result.evidence)
        else:
            broken.extend(_ev([cl]))
    if broken:
        return Outcome(False, _merge(broken))
    return Outcome(True, _merge(supporting))


def _vlan_coverage(cond: VlanCoverageCond, ctx: _Context, bindings: dict[str, str]) -> Outcome:
    spec = cond.vlan_coverage
    rx = ctx.regex(spec.pattern, bindings)
    covered: set[int] = set()
    cover_lines: list[ConfigLine] = []
    defined: set[int] = {1} if spec.include_default_vlan else set()
    vlan_lines: list[ConfigLine] = []
    for cl in ctx.config.lines:
        m = rx.search(cl.text)
        if m is not None and m.group("vlans"):
            covered |= parse_vlan_list(m.group("vlans"))
            cover_lines.append(cl)
        v = _VLAN_LINE_RE.search(cl.text)
        if v is not None:
            defined |= parse_vlan_list(v.group("vlans"))
            vlan_lines.append(cl)
    hit = covered & defined
    if spec.coverage is VlanCoverage.PARTIAL:
        holds = bool(hit) and hit != defined
    elif spec.coverage is VlanCoverage.ALL:
        holds = bool(defined) and hit == defined
    else:
        holds = not hit
    return Outcome(holds, _merge(_ev(cover_lines), _ev(vlan_lines)))


def evaluate(cond: Condition, config: DeviceConfig, facts: DeviceFacts | None = None) -> Outcome:
    """Evaluate one condition against a config (``facts`` is needed for ``platform``)."""
    return _evaluate(cond, _Context(config, facts), {})


@dataclass(frozen=True)
class RuleResult:
    rule_id: str
    advisory_id: str
    exposure: Exposure | None
    verdict: Verdict
    reason: str
    evidence: tuple[Evidence, ...] = ()
    mitigation: str | None = None
    runtime_checks: tuple[RuntimeCheck, ...] = ()


def config_exposure(
    rule: Rule, config: DeviceConfig, facts: DeviceFacts | None
) -> tuple[Exposure, str, tuple[Evidence, ...], str | None]:
    """Config-level exposure, a one-line reason, evidence and the matched mitigation id."""
    ctx = _Context(config, facts)
    exposed = _evaluate(rule.exposure, ctx, {})
    if not exposed.holds:
        return Exposure.ABSENT, "exposure condition not met", exposed.evidence, None
    if rule.affected_platforms is not None:
        pid = ctx.pid()
        if not any(re.search(p, pid) for p in rule.affected_platforms):
            reason = f"feature configured, but platform {pid} is not listed in the advisory"
            return Exposure.NOT_APPLICABLE_PLATFORM, reason, exposed.evidence, None
    for mitigation in rule.mitigations:
        mitigated = _evaluate(mitigation.condition, ctx, {})
        if mitigated.holds:
            reason = f"feature configured, mitigation '{mitigation.id}' in place"
            evidence = _merge(exposed.evidence, mitigated.evidence)
            return Exposure.MITIGATED, reason, evidence, mitigation.id
    return Exposure.PRESENT, "feature configured", exposed.evidence, None


def check_rule(
    rule: Rule,
    config: DeviceConfig,
    facts: DeviceFacts | None,
    version_affected: bool | None = None,
) -> RuleResult:
    """Final verdict for one rule on one device.

    ``version_affected`` comes from the openVuln OS-version data (Phase 5); ``None`` means the
    version was not checked, so a configured feature yields ``INDETERMINATE``.
    """
    try:
        exposure, reason, evidence, mitigation = config_exposure(rule, config, facts)
    except MissingFactsError as exc:
        return RuleResult(
            rule_id=rule.id,
            advisory_id=rule.advisory_id,
            exposure=None,
            verdict=Verdict.INDETERMINATE,
            reason=str(exc),
            runtime_checks=tuple(rule.runtime_checks),
        )
    if exposure in (Exposure.ABSENT, Exposure.NOT_APPLICABLE_PLATFORM):
        verdict = Verdict.NOT_AFFECTED_FEATURE_DISABLED
    elif exposure is Exposure.MITIGATED:
        verdict = Verdict.MITIGATED
    elif version_affected is None:
        verdict = Verdict.INDETERMINATE
        reason += "; software version not checked"
    elif version_affected:
        verdict = Verdict.AFFECTED
    else:
        verdict = Verdict.FIXED_VERSION
        reason += "; running a fixed software version"
    return RuleResult(
        rule_id=rule.id,
        advisory_id=rule.advisory_id,
        exposure=exposure,
        verdict=verdict,
        reason=reason,
        evidence=evidence,
        mitigation=mitigation,
        runtime_checks=tuple(rule.runtime_checks),
    )
