"""LLM rule extraction: advisory text -> draft rule (Phase 4) and its accuracy report."""

from netsec_check.llm.advisory import AdvisoryText, advisory_from_csaf, load_csaf, load_manifest
from netsec_check.llm.backends import (
    Backend,
    BackendError,
    OllamaBackend,
    OpenAICompatibleBackend,
    make_backend,
)
from netsec_check.llm.extract import ExtractionResult, extract_rule, rule_to_yaml

__all__ = [
    "AdvisoryText",
    "Backend",
    "BackendError",
    "ExtractionResult",
    "OllamaBackend",
    "OpenAICompatibleBackend",
    "advisory_from_csaf",
    "extract_rule",
    "load_csaf",
    "load_manifest",
    "make_backend",
    "rule_to_yaml",
]
