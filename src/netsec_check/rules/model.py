"""Rule DSL: a pydantic model for "is the vulnerable feature configured?" rules.

A rule describes, for one advisory, which configuration makes a device exposed. It is data, not
code: the matcher (Phase 3) evaluates it deterministically against a parsed config, and the LLM
(Phase 4) only produces rule documents that must validate against this schema.

Verdict logic the matcher applies to a rule (config level only; the version check comes later):

1. ``exposure`` is false               -> ``absent``
2. ``affected_platforms`` set and the device PID matches none of them
                                       -> ``not_applicable_platform``
3. any ``mitigations[].condition`` true -> ``mitigated``
4. otherwise                           -> ``present``

Conditions
----------
A condition is a mapping with exactly one key that names its kind:

``all_of: [cond, ...]``  every child holds.
``any_of: [cond, ...]``  at least one child holds.
``not: cond``            the child does not hold.
``line: {pattern}``      some global (top-level) config line matches ``pattern``.
``block: {parent, has, lacks, where}``
                         some top-level line matches ``parent`` and, among its descendant lines,
                         every ``has`` pattern matches some line and no ``lacks`` pattern matches
                         any line. Named groups in ``parent`` bind variables for ``has``, ``lacks``
                         and ``where``; ``where`` is an optional condition that must also hold.
``each: {select, capture, require}``
                         for every global line matching ``select``, ``capture`` must match that
                         line and ``require`` must hold with the named groups of ``capture``
                         bound. True when no line matches ``select``.
``platform: [regex, ...]``
                         the device PID (from ``show version``) matches one of the patterns. Use
                         it inside ``exposure`` when the feature cannot exist on other platforms.
``vlan_coverage: {pattern, coverage, include_default_vlan}``
                         collects VLAN ids from the ``vlans`` group of every global line matching
                         ``pattern`` (lists and ranges such as ``10,20-30``) and compares them with
                         the VLANs defined by ``vlan <id>`` lines (plus VLAN 1 if
                         ``include_default_vlan``). ``partial``: at least one but not all;
                         ``all``: every defined VLAN; ``none``: no VLAN.

Patterns are Python regular expressions applied with ``re.search`` to the line text with leading
and trailing whitespace removed, so indentation does not matter. A ``{name}`` placeholder (an
identifier in braces) is replaced by the ``re.escape``-d value of a bound variable before the
pattern is compiled. Placeholders must be bound by an enclosing ``block.parent`` or
``each.capture``.

Remediation hints
-----------------
``mitigations[].snippet`` and ``remediation.snippet`` are IOS XE configuration commands that
reports show next to a finding. They are text only (never evaluated); ``<name>`` marks a value the
operator fills in (an interface, a view name). Upgrading to a fixed release is always the primary
fix. A mitigation snippet applies that workaround; ``remediation`` is a config change that makes
``exposure`` false (turning an unused feature off, or the advisory's own workaround when it is
modelled in ``exposure``).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Discriminator,
    Field,
    Tag,
    field_validator,
    model_validator,
)

PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_]\w*)\}")
KEY_RE = r"^[a-z0-9]+(?:-[a-z0-9]+)*$"


def placeholders(pattern: str) -> set[str]:
    """Return the ``{name}`` placeholders used in a pattern."""
    return set(PLACEHOLDER_RE.findall(pattern))


def fill_placeholders(pattern: str, bindings: dict[str, str]) -> str:
    """Substitute bound variables (regex-escaped) into a pattern."""
    return PLACEHOLDER_RE.sub(lambda m: re.escape(bindings[m.group(1)]), pattern)


def group_names(pattern: str) -> set[str]:
    """Named groups a pattern binds (placeholders are filled with a dummy to compile it)."""
    return set(re.compile(PLACEHOLDER_RE.sub("x", pattern)).groupindex)


def _check_regex(pattern: str) -> str:
    try:
        re.compile(PLACEHOLDER_RE.sub("x", pattern))
    except re.error as exc:
        raise ValueError(f"invalid regex {pattern!r}: {exc}") from exc
    return pattern


Pattern = Annotated[str, Field(min_length=1, description="Python regex (re.search)")]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


# --- leaf conditions -------------------------------------------------------------------------


class LineSpec(_Strict):
    pattern: Pattern

    @field_validator("pattern")
    @classmethod
    def _pattern(cls, v: str) -> str:
        return _check_regex(v)


class BlockSpec(_Strict):
    parent: Pattern
    has: list[Pattern] = Field(default_factory=list)
    lacks: list[Pattern] = Field(default_factory=list)
    where: Condition | None = None

    @field_validator("parent")
    @classmethod
    def _parent(cls, v: str) -> str:
        return _check_regex(v)

    @field_validator("has", "lacks")
    @classmethod
    def _children(cls, v: list[str]) -> list[str]:
        return [_check_regex(p) for p in v]


class EachSpec(_Strict):
    select: Pattern
    capture: Pattern
    require: Condition

    @field_validator("select", "capture")
    @classmethod
    def _patterns(cls, v: str) -> str:
        return _check_regex(v)


class VlanCoverage(StrEnum):
    PARTIAL = "partial"
    ALL = "all"
    NONE = "none"


class VlanCoverageSpec(_Strict):
    pattern: Pattern
    coverage: VlanCoverage
    include_default_vlan: bool = True

    @field_validator("pattern")
    @classmethod
    def _pattern(cls, v: str) -> str:
        _check_regex(v)
        if "vlans" not in group_names(v):
            raise ValueError("vlan_coverage.pattern needs a named group 'vlans'")
        return v


# --- condition wrappers (one key each) -------------------------------------------------------


class AllOf(_Strict):
    all_of: list[Condition] = Field(min_length=1)


class AnyOf(_Strict):
    any_of: list[Condition] = Field(min_length=1)


class Not(_Strict):
    not_: Condition = Field(alias="not")


class Line(_Strict):
    line: LineSpec


class Block(_Strict):
    block: BlockSpec


class Each(_Strict):
    each: EachSpec


class Platform(_Strict):
    platform: list[Pattern] = Field(min_length=1)

    @field_validator("platform")
    @classmethod
    def _patterns(cls, v: list[str]) -> list[str]:
        for p in v:
            _check_regex(p)
            if placeholders(p):
                raise ValueError("platform patterns cannot use placeholders")
        return v


class VlanCoverageCond(_Strict):
    vlan_coverage: VlanCoverageSpec


_KINDS = ("all_of", "any_of", "not", "line", "block", "each", "platform", "vlan_coverage")


def _condition_kind(value: Any) -> str | None:
    if isinstance(value, dict):
        keys = [k for k in value if k in _KINDS]
        if len(value) != 1 or len(keys) != 1:
            return None
        return str(keys[0])
    if isinstance(value, BaseModel):
        return {
            AllOf: "all_of",
            AnyOf: "any_of",
            Not: "not",
            Line: "line",
            Block: "block",
            Each: "each",
            Platform: "platform",
            VlanCoverageCond: "vlan_coverage",
        }.get(type(value))
    return None


Condition = Annotated[
    Annotated[AllOf, Tag("all_of")]
    | Annotated[AnyOf, Tag("any_of")]
    | Annotated[Not, Tag("not")]
    | Annotated[Line, Tag("line")]
    | Annotated[Block, Tag("block")]
    | Annotated[Each, Tag("each")]
    | Annotated[Platform, Tag("platform")]
    | Annotated[VlanCoverageCond, Tag("vlan_coverage")],
    Discriminator(
        _condition_kind,
        custom_error_type="invalid_condition",
        custom_error_message=f"a condition must be a mapping with exactly one key of {_KINDS}",
    ),
]


def children(cond: Condition) -> Iterator[Condition]:
    """Direct child conditions (not including ``block.where`` / ``each.require`` scoping)."""
    if isinstance(cond, AllOf):
        yield from cond.all_of
    elif isinstance(cond, AnyOf):
        yield from cond.any_of
    elif isinstance(cond, Not):
        yield cond.not_


def unbound_placeholders(cond: Condition, bound: frozenset[str] = frozenset()) -> set[str]:
    """Placeholders used in ``cond`` that no enclosing scope binds."""
    missing: set[str] = set()
    if isinstance(cond, Line):
        missing |= placeholders(cond.line.pattern) - bound
    elif isinstance(cond, Block):
        spec = cond.block
        missing |= placeholders(spec.parent) - bound
        inner = bound | group_names(spec.parent)
        for p in (*spec.has, *spec.lacks):
            missing |= placeholders(p) - inner
        if spec.where is not None:
            missing |= unbound_placeholders(spec.where, inner)
    elif isinstance(cond, Each):
        spec_e = cond.each
        missing |= (placeholders(spec_e.select) | placeholders(spec_e.capture)) - bound
        missing |= unbound_placeholders(spec_e.require, bound | group_names(spec_e.capture))
    elif isinstance(cond, VlanCoverageCond):
        missing |= placeholders(cond.vlan_coverage.pattern) - bound
    else:
        for child in children(cond):
            missing |= unbound_placeholders(child, bound)
    return missing


# --- rule ------------------------------------------------------------------------------------


class RuleStatus(StrEnum):
    DRAFT = "draft"
    REVIEWED = "reviewed"


class Mitigation(_Strict):
    id: Annotated[str, Field(pattern=KEY_RE)]
    description: str = Field(min_length=1)
    condition: Condition
    snippet: str | None = Field(
        default=None, min_length=1, description="Config commands that apply this workaround"
    )


class Remediation(_Strict):
    """A config change that removes the exposure (see "Remediation hints" above)."""

    description: str = Field(min_length=1)
    snippet: str = Field(min_length=1, description="Config commands that remove the exposure")


class RuntimeCheck(_Strict):
    """A fact the config cannot show; reported so the operator can confirm it."""

    command: str = Field(min_length=1)
    description: str = Field(min_length=1)


class Rule(_Strict):
    schema_version: Literal[1] = 1
    id: Annotated[str, Field(pattern=KEY_RE, description="Advisory key, e.g. 'webui'")]
    advisory_id: Annotated[str, Field(pattern=r"^cisco-sa-[A-Za-z0-9-]+$")]
    cves: list[Annotated[str, Field(pattern=r"^CVE-\d{4}-\d{4,}$")]] = Field(min_length=1)
    title: str = Field(min_length=1)
    status: RuleStatus
    os: Literal["ios-xe"] = "ios-xe"
    summary: str = Field(min_length=1, description="Human-readable exposure condition")
    exposure: Condition
    affected_platforms: list[Pattern] | None = Field(
        default=None, description="PID patterns; None means every platform running the OS"
    )
    mitigations: list[Mitigation] = Field(default_factory=list)
    runtime_checks: list[RuntimeCheck] = Field(default_factory=list)
    remediation: Remediation | None = None

    @field_validator("affected_platforms")
    @classmethod
    def _platforms(cls, v: list[str] | None) -> list[str] | None:
        if v is not None:
            if not v:
                raise ValueError("affected_platforms must be omitted or non-empty")
            for p in v:
                _check_regex(p)
        return v

    @model_validator(mode="after")
    def _scopes(self) -> Rule:
        conds = [("exposure", self.exposure)]
        conds += [(f"mitigations[{m.id}]", m.condition) for m in self.mitigations]
        for where, cond in conds:
            missing = unbound_placeholders(cond)
            if missing:
                raise ValueError(f"{where}: unbound placeholders {sorted(missing)}")
        ids = [m.id for m in self.mitigations]
        if len(ids) != len(set(ids)):
            raise ValueError("mitigation ids must be unique")
        return self


for _model in (BlockSpec, EachSpec, AllOf, AnyOf, Not, Mitigation, Rule):
    _model.model_rebuild()
