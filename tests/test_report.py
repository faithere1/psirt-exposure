"""Markdown/HTML reports and the CLI report formats."""

from __future__ import annotations

import re
from dataclasses import replace
from html.parser import HTMLParser
from pathlib import Path

import pytest

from netsec_check.check import CheckResult, run_check
from netsec_check.cli import main
from netsec_check.inventory import load_devices
from netsec_check.matcher import Verdict
from netsec_check.psirt import CsafVersionSource, load_kev
from netsec_check.report import ReportMeta, findings, report_html, report_markdown
from netsec_check.rules import load_rules

ROOT = Path(__file__).resolve().parent.parent
RULES = load_rules(ROOT / "rules")
DEVICES = load_devices(ROOT / "samples/configs")
VERSIONS = CsafVersionSource.from_dir(ROOT / "tests/fixtures/psirt")
KEV = load_kev(ROOT / "tests/fixtures/kev/known_exploited_vulnerabilities.json")
# Secret values in the sample configs that evidence must never show.
SECRETS = ("EXAMPLE-RO", "EXAMPLE-RW")


@pytest.fixture(scope="module")
def results() -> list[CheckResult]:
    return run_check(DEVICES, list(RULES.values()), VERSIONS, KEV)


def _counts(results: list[CheckResult]) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in results:
        out[r.result.verdict.value] = out.get(r.result.verdict.value, 0) + 1
    return out


def test_findings_order_and_scope(results: list[CheckResult]) -> None:
    found = findings(results, RULES)
    verdicts = [f.verdict for f in found]
    assert set(verdicts) == {Verdict.AFFECTED, Verdict.INDETERMINATE, Verdict.MITIGATED}
    order = [Verdict.AFFECTED, Verdict.INDETERMINATE, Verdict.MITIGATED]
    assert verdicts == sorted(verdicts, key=order.index)
    counts = _counts(results)
    assert len(found) == counts["AFFECTED"] + counts["INDETERMINATE"] + counts["MITIGATED"]


def test_snippets(results: list[CheckResult]) -> None:
    by_key = {(f.item.device.name, f.rule.id): f for f in findings(results, RULES)}
    webui = by_key["access-sw-01", "webui"]
    assert webui.verdict is Verdict.AFFECTED
    labels = [s.label for s in webui.snippets()]
    assert labels == ["Workaround (session-modules-none)", "Remove the exposure"]
    assert "no ip http server" in webui.snippets()[1].commands
    mitigated = next(f for f in by_key.values() if f.verdict is Verdict.MITIGATED)
    assert mitigated.snippets() == []


def test_markdown(results: list[CheckResult]) -> None:
    md = report_markdown(results, RULES, ReportMeta(generated="2026-01-01", sources={"KEV": "x"}))
    assert md.startswith("# netsec-check report\n\nGenerated: 2026-01-01 · KEV: x\n")
    for verdict, n in _counts(results).items():
        assert f"| {verdict} | {n} |" in md
    assert "### access-sw-01 · webui · AFFECTED" in md
    assert "```text\nno ip http server\nno ip http secure-server\n```" in md
    assert "Mitigation in place: `exclude-affected-oid`." in md
    assert "**CISA KEV:** CVE-2023-20198" in md
    assert "`show ip dhcp snooping`" in md
    assert not any(s in md for s in SECRETS)
    assert "<redacted>" in md
    assert md == report_markdown(
        results, RULES, ReportMeta(generated="2026-01-01", sources={"KEV": "x"})
    )


def test_markdown_no_findings(results: list[CheckResult]) -> None:
    quiet = [r for r in results if r.result.verdict is Verdict.NOT_AFFECTED_FEATURE_DISABLED]
    assert "No device is affected" in report_markdown(quiet, RULES)


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)

    def handle_data(self, data: str) -> None:
        self.text.append(data)


def test_html(results: list[CheckResult]) -> None:
    page = report_html(results, RULES, ReportMeta(generated="2026-01-01"))
    assert page.startswith("<!DOCTYPE html>")
    parser = _Collector()
    parser.feed(page)
    assert "script" not in parser.tags
    text = "".join(parser.text)
    assert "access-sw-01 · webui · AFFECTED" in text
    assert "no ip http server" in text
    assert not any(s in page for s in SECRETS)
    # Evidence is escaped: the redaction marker never appears as a raw tag.
    assert "&lt;redacted&gt;" in page and "<redacted>" not in page


def test_html_escapes_device_names(results: list[CheckResult]) -> None:
    item = next(r for r in results if r.result.verdict is Verdict.AFFECTED)
    evil = replace(item, device=replace(item.device, name="<script>x</script>"))
    page = report_html([evil], RULES)
    assert "<script>x" not in page and "&lt;script&gt;x" in page
    md = report_markdown([replace(evil, device=replace(item.device, name="a|b"))], RULES)
    assert "| a\\|b |" in md


@pytest.mark.parametrize(
    ("fmt", "marker"), [("markdown", "# netsec-check report"), ("html", "<!DOCTYPE html>")]
)
def test_cli_report(
    fmt: str, marker: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    base = ["check", "--offline", "--configs", str(ROOT / "samples/configs")]
    base += ["--rules", str(ROOT / "rules"), "--advisories", str(ROOT / "tests/fixtures/psirt")]
    assert main([*base, "--format", fmt]) == 0
    out = capsys.readouterr().out
    assert out.startswith(marker)
    assert re.search(r"Versions: csaf · KEV: none", out)
    target = tmp_path / f"report.{fmt}"
    assert main([*base, "--format", fmt, "--output", str(target)]) == 0
    assert capsys.readouterr().out == ""
    assert target.read_text(encoding="utf-8") == out
