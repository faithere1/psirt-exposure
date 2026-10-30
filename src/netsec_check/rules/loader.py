"""Load and validate rule YAML files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from netsec_check.rules.model import Rule


class RuleLoadError(ValueError):
    """A rule file is unreadable or does not match the schema."""


def load_rule(path: Path) -> Rule:
    """Parse one rule file; the file name (without ``.yaml``) must equal the rule id."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise RuleLoadError(f"{path}: top level must be a mapping")
    try:
        rule = Rule.model_validate(data)
    except ValueError as exc:
        raise RuleLoadError(f"{path}: {exc}") from exc
    if rule.id != path.stem:
        raise RuleLoadError(f"{path}: id {rule.id!r} does not match file name")
    return rule


def load_rules(directory: Path) -> dict[str, Rule]:
    """Load every ``*.yaml`` rule in a directory, keyed by rule id."""
    rules: dict[str, Rule] = {}
    for path in sorted(directory.glob("*.yaml")):
        rule = load_rule(path)
        rules[rule.id] = rule
    return rules


def rule_json_schema() -> dict[str, Any]:
    """JSON Schema of a rule document (used for schema-constrained LLM output)."""
    return Rule.model_json_schema(by_alias=True)


def dump_json_schema(path: Path) -> None:
    path.write_text(json.dumps(rule_json_schema(), indent=2) + "\n", encoding="utf-8")
