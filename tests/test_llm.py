"""LLM extraction (Phase 4): prompts, backends, validation/retry loop and the accuracy report.

No model is called: backends are faked or run against ``httpx.MockTransport``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from netsec_check import cli
from netsec_check.inventory import load_devices
from netsec_check.llm import evaluate
from netsec_check.llm.advisory import load_csaf, load_manifest
from netsec_check.llm.backends import (
    BackendError,
    OllamaBackend,
    OpenAICompatibleBackend,
    make_backend,
)
from netsec_check.llm.extract import (
    EXAMPLE_RULE,
    ExtractedRule,
    bounded_schema,
    extract_rule,
    extraction_schema,
    rule_to_yaml,
    system_prompt,
)
from netsec_check.rules import RuleStatus, load_rule, load_rules

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "tests/fixtures/psirt/manifest.yaml"
SOURCES = load_manifest(MANIFEST)
HAND = load_rules(ROOT / "rules")
LABELS = evaluate.load_labels(ROOT / "samples/configs/labels.yaml")
DEVICES = load_devices(ROOT / "samples/configs")
META = ("schema_version", "id", "advisory_id", "cves", "title", "status", "os")


def _body(key: str) -> str:
    """The LLM-written part of a hand rule, as a model reply."""
    data = HAND[key].model_dump(mode="json", by_alias=True, exclude_none=True)
    return json.dumps({k: v for k, v in data.items() if k not in META})


class FakeBackend:
    name = "fake:test"

    def __init__(self, replies: list[str]) -> None:
        self.replies = replies
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def generate(self, system: str, user: str, schema: dict[str, Any]) -> str:
        self.calls.append((system, user, schema))
        if not self.replies:
            raise BackendError("no more replies")
        return self.replies.pop(0)


# --- advisory text and prompt ----------------------------------------------------------------


def test_manifest_lists_every_hand_rule() -> None:
    assert set(SOURCES) == set(HAND)


@pytest.mark.parametrize("key", sorted(HAND))
def test_advisory_metadata_matches_hand_rule(key: str) -> None:
    adv = load_csaf(SOURCES[key])
    rule = HAND[key]
    assert adv.advisory_id == rule.advisory_id
    assert list(adv.cves) == sorted(rule.cves)
    assert adv.title == rule.title


def test_prompt_text_has_feature_sections_only() -> None:
    text = load_csaf(SOURCES["dhcp-snooping"]).prompt_text()
    assert "## Vulnerable Products" in text
    assert "## Workarounds" in text
    assert "Fixed Software" not in text.split("## ")[0]
    assert "## Fixed Software" not in text
    assert "\r" not in text


def test_example_rule_is_valid_and_not_a_fixture() -> None:
    ExtractedRule.model_validate(EXAMPLE_RULE)
    prompt = system_prompt()
    assert "exporter-sanitize" in prompt
    for key in HAND:
        assert HAND[key].advisory_id not in prompt


def test_extraction_schema_is_the_rule_body() -> None:
    schema = extraction_schema()
    assert set(schema["properties"]) == {
        "summary",
        "exposure",
        "affected_platforms",
        "mitigations",
        "runtime_checks",
        "remediation",
    }
    assert schema["required"] == ["summary", "exposure"]
    assert "not" in schema["$defs"]["Not"]["properties"]


# --- extraction loop -------------------------------------------------------------------------


@pytest.mark.parametrize("key", sorted(HAND))
def test_extract_hand_rule_body_round_trips(key: str, tmp_path: Path) -> None:
    backend = FakeBackend([_body(key)])
    result = extract_rule(key, load_csaf(SOURCES[key]), backend)
    assert result.rule is not None
    assert result.attempts == 1 and not result.errors
    assert result.rule.status is RuleStatus.DRAFT
    expected = HAND[key].model_copy(update={"status": RuleStatus.DRAFT})
    assert result.rule == expected
    path = tmp_path / f"{key}.yaml"
    path.write_text(rule_to_yaml(result.rule), encoding="utf-8")
    assert load_rule(path) == expected


def test_metadata_is_never_taken_from_the_model() -> None:
    reply = json.loads(_body("iox")) | {"advisory_id": "cisco-sa-fake-1234"}
    result = extract_rule("iox", load_csaf(SOURCES["iox"]), FakeBackend([json.dumps(reply)]), 1)
    assert result.rule is None  # extra keys are rejected, not silently accepted


def test_retry_feeds_validation_error_back() -> None:
    bad = json.dumps({"summary": "x", "exposure": {"line": {"pattern": "("}}})
    backend = FakeBackend(["not json", bad, _body("cip")])
    result = extract_rule("cip", load_csaf(SOURCES["cip"]), backend)
    assert result.rule is not None
    assert result.attempts == 3
    assert "not valid JSON" in result.errors[0]
    assert "invalid regex" in result.errors[1]
    assert "Validation errors" in backend.calls[2][1]
    assert bad in backend.calls[2][1]


def test_unbound_placeholder_is_rejected() -> None:
    reply = json.dumps({"summary": "x", "exposure": {"line": {"pattern": "^crypto map {map}$"}}})
    result = extract_rule("ikev2", load_csaf(SOURCES["ikev2"]), FakeBackend([reply]), 1)
    assert result.rule is None
    assert "unbound placeholders" in result.errors[0]


def test_backend_error_stops_without_retry() -> None:
    backend = FakeBackend([])
    result = extract_rule("snmp", load_csaf(SOURCES["snmp"]), backend)
    assert result.rule is None and result.attempts == 1
    assert result.errors == ["no more replies"]


# --- backends --------------------------------------------------------------------------------


def _client(handler: Any) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_ollama_backend_sends_schema_as_format() -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"message": {"role": "assistant", "content": "{}"}})

    backend = OllamaBackend(
        model="m", base_url="http://ollama.invalid:11434/", client=_client(handler)
    )
    assert backend.generate("sys", "usr", {"type": "object"}) == "{}"
    assert seen["url"] == "http://ollama.invalid:11434/api/chat"
    assert seen["body"]["format"] == {"type": "object"}
    assert seen["body"]["stream"] is False
    assert seen["body"]["options"]["temperature"] == 0.0
    assert [m["role"] for m in seen["body"]["messages"]] == ["system", "user"]
    assert backend.name == "ollama:m"


def test_ollama_backend_http_error() -> None:
    backend = OllamaBackend(client=_client(lambda r: httpx.Response(404, text="model not found")))
    with pytest.raises(BackendError, match="HTTP 404"):
        backend.generate("s", "u", {})


def test_openai_backend_uses_json_schema_and_env_key(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})

    monkeypatch.setenv("NETSEC_TEST_KEY", "test-key-not-real")
    backend = OpenAICompatibleBackend(
        model="m",
        base_url="http://llm.invalid/v1",
        api_key_env="NETSEC_TEST_KEY",
        client=_client(handler),
    )
    assert backend.generate("s", "u", {"type": "object"}) == "{}"
    assert seen["url"] == "http://llm.invalid/v1/chat/completions"
    assert seen["auth"] == "Bearer test-key-not-real"
    fmt = seen["body"]["response_format"]
    assert fmt["type"] == "json_schema" and fmt["json_schema"]["schema"] == {"type": "object"}


def test_openai_backend_without_key_sends_no_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    def handler(request: httpx.Request) -> httpx.Response:
        assert "authorization" not in request.headers
        return httpx.Response(200, json={"choices": []})

    backend = OpenAICompatibleBackend(model="m", client=_client(handler))
    with pytest.raises(BackendError, match="unexpected response"):
        backend.generate("s", "u", {})


def test_make_backend() -> None:
    assert make_backend("ollama").name.startswith("ollama:")
    assert make_backend("openai", "gpt-x", "http://llm.invalid/v1").name == "openai:gpt-x"
    with pytest.raises(ValueError, match="needs --model"):
        make_backend("openai")
    with pytest.raises(ValueError, match="unknown backend"):
        make_backend("other")


# --- evaluation ------------------------------------------------------------------------------


def test_score_hand_rules_as_drafts_are_perfect() -> None:
    keys = sorted(HAND)
    scores = evaluate.score(keys, HAND, dict(HAND), DEVICES, LABELS)
    s = evaluate.summary(scores)
    assert s["cells"] == 80
    assert s["draft_correct"] == s["hand_correct"] == s["draft_agrees_hand"] == 80
    assert s["exact_rules"] == 10
    assert s["baseline_always_absent"] == 57


def test_score_missing_and_wrong_drafts() -> None:
    drafts = {"iox": HAND["webui"].model_copy(update={"id": "iox"}), "cip": None}
    scores = {s.key: s for s in evaluate.score(["iox", "cip"], HAND, drafts, DEVICES, LABELS)}
    assert not scores["cip"].valid
    assert {c.draft for c in scores["cip"].cells} == {evaluate.MISSING}
    assert scores["iox"].valid and not scores["iox"].exact
    report = evaluate.report_markdown(list(scores.values()), {"backend": "fake"})
    assert "## Mismatches" in report and "| iox |" in report


def test_cli_extract_then_eval(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    replies = [_body(k) for k in ("iox", "webui")] + ["{}", "{}", "{}"]
    backend = FakeBackend(replies)
    monkeypatch.setattr(cli, "make_backend", lambda *a: backend)
    drafts = tmp_path / "fake" / "rules"
    argv = ["extract", "--manifest", str(MANIFEST), "--out", str(drafts)]
    rc = cli.main([*argv, "--key", "iox", "--key", "webui", "--key", "cip"])
    assert rc == 1  # cip failed
    assert sorted(p.name for p in drafts.iterdir()) == ["extraction.json", "iox.yaml", "webui.yaml"]
    log = json.loads((drafts / "extraction.json").read_text())
    assert log["advisories"]["cip"]["attempts"] == 3

    rc = cli.main(
        [
            "eval-extraction",
            "--drafts",
            str(drafts),
            "--rules",
            str(ROOT / "rules"),
            "--configs",
            str(ROOT / "samples/configs"),
            "--labels",
            str(ROOT / "samples/configs/labels.yaml"),
        ]
    )
    assert rc == 0
    report = (tmp_path / "fake" / "report.md").read_text()
    assert "fake:test" in report
    data = json.loads((tmp_path / "fake" / "report.json").read_text())
    assert data["summary"]["valid"] == 2


def test_mitigation_ids_are_normalized() -> None:
    reply = json.loads(_body("nat-dns-alg"))
    reply["mitigations"][0]["id"] = "Disable_DNS ALG"
    result = extract_rule(
        "nat-dns-alg", load_csaf(SOURCES["nat-dns-alg"]), FakeBackend([json.dumps(reply)])
    )
    assert result.rule is not None
    assert result.rule.mitigations[0].id == "disable-dns-alg"


def test_bounded_schema_has_no_cycles_or_patterns() -> None:
    schema = bounded_schema(extraction_schema(), max_depth=3)
    text = json.dumps(schema)
    assert '"pattern": "^' not in text
    defs = schema["$defs"]
    assert "LineSpec_1" in defs and "AllOf_2" in defs and "AllOf_3" not in defs
    # property *names* called "pattern" survive
    assert defs["LineSpec_1"]["required"] == ["pattern"]
    assert "pattern" in defs["LineSpec_1"]["properties"]

    # every $ref points to a definition at the same or a deeper level: no cycles
    def refs(node: Any) -> list[str]:
        if isinstance(node, dict):
            own = [node["$ref"].rsplit("/", 1)[1]] if "$ref" in node else []
            return own + [r for v in node.values() for r in refs(v)]
        if isinstance(node, list):
            return [r for v in node for r in refs(v)]
        return []

    for name, body in defs.items():
        level = int(name.rsplit("_", 1)[1])
        assert all(int(r.rsplit("_", 1)[1]) >= level for r in refs(body))
        assert name not in refs(body)
