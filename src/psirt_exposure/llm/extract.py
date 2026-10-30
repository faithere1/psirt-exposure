"""Turn advisory text into a draft rule with an LLM.

The model only fills the condition part of a rule (``ExtractedRule``); its reply is constrained by
the JSON Schema of that model and validated with the same pydantic rules as hand-written YAML.
Identifiers come from the CSAF document, and the result always has status ``draft``. Invalid
replies are sent back to the model with the validation error, up to ``max_attempts`` times.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

import yaml
from pydantic import Field, ValidationError

from psirt_exposure.llm.advisory import AdvisoryText
from psirt_exposure.llm.backends import Backend, BackendError
from psirt_exposure.rules import model as dsl
from psirt_exposure.rules.model import (
    Condition,
    Mitigation,
    Remediation,
    Rule,
    RuleStatus,
    RuntimeCheck,
)


class ExtractedRule(dsl._Strict):
    """The part of a rule the LLM writes."""

    summary: str = Field(min_length=1, description="One or two sentences: when is a device exposed")
    exposure: Condition
    affected_platforms: list[dsl.Pattern] | None = None
    mitigations: list[Mitigation] = Field(default_factory=list)
    runtime_checks: list[RuntimeCheck] = Field(default_factory=list)
    remediation: Remediation | None = None


MAX_CONDITION_DEPTH = 4
# "pattern" crashes Ollama's schema-to-grammar converter (seen with Ollama 0.15); the other keys
# only add size. Pydantic still enforces all of them when the reply is validated.
_DROPPED_KEYWORDS = ("$defs", "title", "default", "pattern")


def extraction_schema() -> dict[str, Any]:
    """Full (recursive) JSON Schema of ``ExtractedRule``."""
    return ExtractedRule.model_json_schema(by_alias=True)


def bounded_schema(schema: dict[str, Any], max_depth: int = MAX_CONDITION_DEPTH) -> dict[str, Any]:
    """Unroll the recursive condition union into ``max_depth`` levels without ``$ref`` cycles.

    Grammar-based decoders (Ollama / llama.cpp) cannot handle recursive schemas, so each nesting
    level gets its own copies of the condition definitions (``Line_1``, ``AllOf_2``, ...). At the
    last level only leaf conditions (those that cannot contain another condition) are allowed.
    ``pattern`` constraints are dropped (see ``_DROPPED_KEYWORDS``).
    Pydantic still validates the reply against the full model afterwards.
    """
    defs: dict[str, Any] = schema.get("$defs", {})
    kinds = [r["$ref"].rsplit("/", 1)[1] for r in schema["properties"]["exposure"]["oneOf"]]

    def refs(node: Any) -> set[str]:
        if isinstance(node, dict):
            found = {node["$ref"].rsplit("/", 1)[1]} if "$ref" in node else set()
            return found.union(*(refs(v) for v in node.values()))
        if isinstance(node, list):
            return set().union(*(refs(v) for v in node))
        return set()

    def nests(name: str, seen: frozenset[str] = frozenset()) -> bool:
        inner = refs(defs[name]) - seen
        return any(r in kinds or nests(r, seen | {name}) for r in inner)

    leaves = [k for k in kinds if not nests(k)]
    out: dict[str, Any] = {}

    def is_union(node: dict[str, Any]) -> bool:
        alts = node.get("oneOf")
        return isinstance(alts, list) and {
            a.get("$ref", "").rsplit("/", 1)[-1] for a in alts
        } == set(kinds)

    def define(name: str, depth: int) -> str:
        target = f"{name}_{depth}"
        if target not in out:
            out[target] = {}  # reserve the name before recursing
            out[target] = rewrite(defs[name], depth)
        return f"#/$defs/{target}"

    def rewrite(node: Any, depth: int) -> Any:
        if isinstance(node, list):
            return [rewrite(v, depth) for v in node]
        if not isinstance(node, dict):
            return node
        if is_union(node):
            allowed = kinds if depth + 1 < max_depth else leaves
            return {"anyOf": [{"$ref": define(k, depth + 1)} for k in allowed]}
        if "$ref" in node:
            return {"$ref": define(node["$ref"].rsplit("/", 1)[1], depth)}
        out_node: dict[str, Any] = {}
        for k, v in node.items():
            if k == "properties":  # property names are not keywords
                out_node[k] = {name: rewrite(sub, depth) for name, sub in v.items()}
            elif k not in _DROPPED_KEYWORDS:
                out_node[k] = rewrite(v, depth)
        return out_node

    top: dict[str, Any] = rewrite(schema, 0)
    top["$defs"] = out
    return top


# A made-up advisory, so the example never leaks the answer for a real fixture.
EXAMPLE_ADVISORY = """\
Advisory: cisco-sa-example-netflow (FICTIONAL EXAMPLE)
## Vulnerable Products
This vulnerability affects Cisco ISR 4000 Series and Catalyst 8500 Series Edge Platforms if they
run a vulnerable release of Cisco IOS XE Software and have a Flexible NetFlow monitor that uses an
exporter applied to at least one interface. To check, run show running-config | section flow.
## Workarounds
Configure "flow exporter-options sanitize" globally; the feature keeps working."""

EXAMPLE_RULE: dict[str, Any] = {
    "summary": (
        "A flow monitor with an exporter is applied to an interface. Only ISR 4000 and "
        "Catalyst 8500 are affected; 'flow exporter-options sanitize' mitigates."
    ),
    "exposure": {
        "block": {
            "parent": r"^flow monitor (?P<mon>\S+)$",
            "has": [r"^exporter \S+"],
            "where": {
                "block": {
                    "parent": "^interface ",
                    "has": [r"^ip flow monitor {mon} (input|output)$"],
                }
            },
        }
    },
    "affected_platforms": [r"^ISR4\d\d\d", r"^C85\d\d"],
    "mitigations": [
        {
            "id": "exporter-sanitize",
            "description": "Global 'flow exporter-options sanitize' is configured.",
            "condition": {"line": {"pattern": "^flow exporter-options sanitize$"}},
        }
    ],
    "runtime_checks": [
        {"command": "show flow monitor", "description": "Lists monitors in use on interfaces."}
    ],
}

GUIDELINES = """\
How to write the rule:
- Describe only the CONFIGURATION that makes a device exposed. Ignore software versions
  completely; they are checked elsewhere.
- Patterns match ONE line of "show running-config" (IOS XE syntax, leading spaces removed).
  Anchor them with ^ and, when the whole line is known, $. Use \\S+ for names and numbers.
- Use "line" for a global command, "block" for a section (interface, crypto map, line vty, ...)
  and its sub-commands. Named groups in block.parent bind {placeholders} for nested conditions.
- Use "all_of" when the advisory requires several features together ("and"), "any_of" for
  alternatives ("or", "either").
- Set "affected_platforms" (regexes over the product ID, such as ^C83\\d\\d or ^ISR4\\d\\d\\d)
  only when the advisory limits the feature condition to listed hardware. Otherwise omit it.
- Use "platform" inside "exposure" only when the feature cannot exist on other hardware.
- "mitigations" are configuration workarounds that keep the feature on but remove the risk.
  Turning the feature off is NOT a mitigation (the exposure condition is then false). If the
  advisory says there are no workarounds, return an empty list.
- Facts the configuration cannot show (active sessions, open ports, running services) go into
  "runtime_checks" with the show command from the advisory, never into conditions.
- Mitigation ids are short kebab-case labels such as "disable-feature-x".
- "snippet" (in a mitigation) and "remediation.snippet" are IOS XE config commands copied from the
  advisory's workaround text; write <name> for values the operator fills in. Omit them otherwise.
- Reply with a single JSON object that matches the schema, nothing else."""


def system_prompt() -> str:
    return "\n\n".join(
        [
            "You convert Cisco security advisories into machine-checkable rules for a "
            "configuration scanner. The rule language is defined below.",
            "# Rule language\n" + (dsl.__doc__ or ""),
            "# " + GUIDELINES,
            "# Example\nAdvisory text:\n"
            + EXAMPLE_ADVISORY
            + "\n\nRule JSON:\n"
            + json.dumps(EXAMPLE_RULE, indent=2),
        ]
    )


@dataclass
class ExtractionResult:
    key: str
    backend: str
    rule: Rule | None
    attempts: int
    errors: list[str] = field(default_factory=list)
    raw: list[str] = field(default_factory=list)


def _to_rule(key: str, advisory: AdvisoryText, reply: str) -> Rule:
    try:
        data = json.loads(reply)
    except json.JSONDecodeError as exc:
        raise ValueError(f"reply is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("reply must be a JSON object")
    # Mitigation ids are labels only; normalize them instead of spending a retry on "disable_x".
    for m in data.get("mitigations") or []:
        if isinstance(m, dict) and isinstance(m.get("id"), str):
            m["id"] = re.sub(r"[^a-z0-9]+", "-", m["id"].lower()).strip("-") or "mitigation"
    extracted = ExtractedRule.model_validate(data)
    return Rule.model_validate(
        {
            "id": key,
            "advisory_id": advisory.advisory_id,
            "cves": list(advisory.cves),
            "title": advisory.title,
            "status": RuleStatus.DRAFT,
            **extracted.model_dump(by_alias=True, exclude_none=True),
        }
    )


def _short_error(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        errs = exc.errors()
        lines = [f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in errs[:8]]
        if len(errs) > 8:
            lines.append(f"... and {len(errs) - 8} more")
        return "\n".join(lines)
    return str(exc)


def extract_rule(
    key: str, advisory: AdvisoryText, backend: Backend, max_attempts: int = 3
) -> ExtractionResult:
    schema = bounded_schema(extraction_schema())
    system = system_prompt()
    base = "Advisory text:\n" + advisory.prompt_text() + "\n\nRule JSON:"
    user = base
    result = ExtractionResult(key=key, backend=backend.name, rule=None, attempts=0)
    for _ in range(max_attempts):
        result.attempts += 1
        try:
            reply = backend.generate(system, user, schema)
        except BackendError as exc:
            result.errors.append(str(exc))
            break
        result.raw.append(reply)
        try:
            result.rule = _to_rule(key, advisory, reply)
            return result
        except ValueError as exc:  # ValidationError is a ValueError
            error = _short_error(exc)
            result.errors.append(error)
            user = (
                f"{base}\n\nYour previous reply was rejected:\n{reply}\n\n"
                f"Validation errors:\n{error}\n\nReturn a corrected rule JSON."
            )
    return result


def rule_to_yaml(rule: Rule) -> str:
    data = rule.model_dump(mode="json", by_alias=True, exclude_none=True)
    for name in ("mitigations", "runtime_checks"):
        if not data.get(name):
            data.pop(name, None)
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100)
