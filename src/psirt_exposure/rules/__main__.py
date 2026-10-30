"""Regenerate rules/rule.schema.json: ``PYTHONPATH=src uv run python -m psirt_exposure.rules``."""

from __future__ import annotations

import sys
from pathlib import Path

from psirt_exposure.rules.loader import dump_json_schema

target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("rules/rule.schema.json")
dump_json_schema(target)
print(f"wrote {target}")
