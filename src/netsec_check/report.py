"""Markdown and HTML reports for check results, with remediation snippets.

Reports only use redacted ``Evidence.text`` and the rule's own snippets; raw config lines never
reach them. Output is deterministic for the same input (the caller supplies any timestamp).
"""

from __future__ import annotations

import html
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from netsec_check.check import CheckResult
from netsec_check.matcher import Verdict
from netsec_check.rules import Rule

ADVISORY_URL = (
    "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/{advisory_id}"
)
# Most urgent first; also the column order of the device table.
VERDICT_ORDER = (
    Verdict.AFFECTED,
    Verdict.INDETERMINATE,
    Verdict.MITIGATED,
    Verdict.FIXED_VERSION,
    Verdict.NOT_AFFECTED_FEATURE_DISABLED,
)
# Verdicts that get a findings section; the others only appear as counts.
FINDING_VERDICTS = frozenset({Verdict.AFFECTED, Verdict.INDETERMINATE, Verdict.MITIGATED})
UPGRADE = (
    "Upgrade to a fixed release listed in the advisory (or check the running version with the "
    "Cisco Software Checker)."
)


@dataclass(frozen=True)
class ReportMeta:
    """Header facts; ``sources`` maps a label (e.g. "Versions") to a short description."""

    title: str = "netsec-check report"
    generated: str | None = None
    sources: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Snippet:
    label: str
    description: str
    commands: str


@dataclass(frozen=True)
class Finding:
    item: CheckResult
    rule: Rule

    @property
    def verdict(self) -> Verdict:
        return self.item.result.verdict

    @property
    def advisory_url(self) -> str:
        return ADVISORY_URL.format(advisory_id=self.rule.advisory_id)

    def snippets(self) -> list[Snippet]:
        """Workaround and remediation snippets; none once a mitigation is in place."""
        if self.verdict is Verdict.MITIGATED:
            return []
        out = [
            Snippet(f"Workaround ({m.id})", m.description, m.snippet)
            for m in self.rule.mitigations
            if m.snippet
        ]
        if self.rule.remediation:
            rem = self.rule.remediation
            out.append(Snippet("Remove the exposure", rem.description, rem.snippet))
        return out


def findings(results: Sequence[CheckResult], rules: Mapping[str, Rule]) -> list[Finding]:
    """Results that need attention, most urgent verdict first, then by device and rule."""
    rank = {v: i for i, v in enumerate(VERDICT_ORDER)}
    picked = [
        Finding(r, rules[r.result.rule_id]) for r in results if r.result.verdict in FINDING_VERDICTS
    ]
    return sorted(
        picked, key=lambda f: (rank[f.verdict], f.item.device.name, f.item.result.rule_id)
    )


@dataclass(frozen=True)
class _DeviceRow:
    name: str
    platform: str
    version: str
    counts: Counter[Verdict]


def _device_rows(results: Sequence[CheckResult]) -> list[_DeviceRow]:
    rows: dict[str, _DeviceRow] = {}
    for r in results:
        d = r.device
        if d.name not in rows:
            rows[d.name] = _DeviceRow(
                d.name,
                d.facts.pid if d.facts else "-",
                d.facts.version if d.facts else "-",
                Counter(),
            )
        rows[d.name].counts[r.result.verdict] += 1
    return [rows[k] for k in sorted(rows)]


def _kev_text(f: Finding) -> str:
    return "; ".join(
        f"{k.cve} (added {k.date_added}, due {k.due_date}"
        + (", known ransomware use" if k.known_ransomware_use.lower() == "known" else "")
        + ")"
        for k in f.item.kev
    )


def _short(v: Verdict) -> str:
    return "NOT_AFFECTED" if v is Verdict.NOT_AFFECTED_FEATURE_DISABLED else v.value


# --- Markdown --------------------------------------------------------------------------------


def _cell(text: str) -> str:
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def _code(text: str) -> str:
    """Inline code span that survives backticks in ``text``."""
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    ticks = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{ticks}{pad}{text}{pad}{ticks}"


def _fence(text: str) -> list[str]:
    longest = max((len(m) for m in re.findall(r"`{3,}", text)), default=2)
    ticks = "`" * (longest + 1)
    return [f"{ticks}text", text, ticks]


def report_markdown(
    results: Sequence[CheckResult], rules: Mapping[str, Rule], meta: ReportMeta | None = None
) -> str:
    meta = meta or ReportMeta()
    out = [f"# {meta.title}", ""]
    header = [f"Generated: {meta.generated}"] if meta.generated else []
    header += [f"{k}: {v}" for k, v in meta.sources.items()]
    if header:
        out += [" · ".join(header), ""]

    totals = Counter(r.result.verdict for r in results)
    devices = _device_rows(results)
    out += ["## Summary", ""]
    out += [f"{len(devices)} devices, {len({r.result.rule_id for r in results})} rules.", ""]
    out += ["| Verdict | Count |", "|---|---:|"]
    out += [f"| {v.value} | {totals[v]} |" for v in VERDICT_ORDER]
    out += ["", "## Devices", ""]
    out.append("| Device | Platform | Version | " + " | ".join(map(_short, VERDICT_ORDER)) + " |")
    out.append("|---|---|---|" + "---:|" * len(VERDICT_ORDER))
    for row in devices:
        counts = " | ".join(str(row.counts[v]) for v in VERDICT_ORDER)
        cells = " | ".join(_cell(c) for c in (row.name, row.platform, row.version))
        out.append(f"| {cells} | {counts} |")

    found = findings(results, rules)
    out += ["", "## Findings", ""]
    if not found:
        out += ["No device is affected, indeterminate or mitigated.", ""]
    for f in found:
        res, rule = f.item.result, f.rule
        out += [f"### {_cell(f.item.device.name)} · {rule.id} · {f.verdict.value}", ""]
        out.append(f"**{_cell(rule.title)}**  ")
        out.append(f"Advisory: [{rule.advisory_id}]({f.advisory_url}) · {', '.join(rule.cves)}")
        if f.item.kev:
            out.append(f"  \n**CISA KEV:** {_kev_text(f)}")
        out += ["", f"Why: {res.reason}", ""]
        if res.evidence:
            out += ["Evidence:", "", *_fence("\n".join(str(e) for e in res.evidence)), ""]
        if res.runtime_checks:
            out += ["Confirm on the device:", ""]
            out += [f"- {_code(c.command)}: {c.description}" for c in res.runtime_checks]
            out.append("")
        if f.verdict is Verdict.MITIGATED:
            out += [f"Mitigation in place: {_code(res.mitigation or '-')}.", ""]
            continue
        out += [f"Fix: {UPGRADE}", ""]
        for s in f.snippets():
            out += [f"{s.label}: {s.description}", "", *_fence(s.commands), ""]
    return "\n".join(out).rstrip("\n") + "\n"


# --- HTML ------------------------------------------------------------------------------------

_CSS = """
:root { color-scheme: light dark; --fg: #1d1d1f; --bg: #fff; --muted: #6e6e73;
  --line: #d2d2d7; --code: #f5f5f7; --bad: #b3261e; --warn: #8a5300; --ok: #1b6e3a; }
@media (prefers-color-scheme: dark) { :root { --fg: #f5f5f7; --bg: #1c1c1e; --muted: #a1a1a6;
  --line: #3a3a3c; --code: #2c2c2e; --bad: #ff6b60; --warn: #f0b34a; --ok: #5fd68a; } }
body { font: 15px/1.5 system-ui, sans-serif; color: var(--fg); background: var(--bg);
  max-width: 960px; margin: 2rem auto; padding: 0 1rem; }
h1, h2, h3 { line-height: 1.25; } h3 { margin-top: 2rem; }
.meta, .muted { color: var(--muted); }
table { border-collapse: collapse; margin: 1rem 0; }
th, td { border-bottom: 1px solid var(--line); padding: .3rem .8rem; text-align: left; }
td.n, th.n { text-align: right; font-variant-numeric: tabular-nums; }
pre, code { font: 13px/1.45 ui-monospace, Menlo, monospace; background: var(--code); }
pre { padding: .6rem .8rem; border-radius: 6px; overflow-x: auto; }
code { padding: 0 .25rem; border-radius: 4px; }
.v { font-weight: 600; }
.AFFECTED { color: var(--bad); } .INDETERMINATE { color: var(--warn); }
.MITIGATED, .FIXED_VERSION, .NOT_AFFECTED_FEATURE_DISABLED { color: var(--ok); }
section.finding { border-top: 1px solid var(--line); }
""".strip()


def _e(text: str) -> str:
    return html.escape(text, quote=True)


def _verdict(v: Verdict) -> str:
    return f'<span class="v {v.value}">{_e(v.value)}</span>'


def _pre(text: str) -> str:
    return f"<pre><code>{_e(text)}</code></pre>"


def _finding_html(f: Finding) -> list[str]:
    res, rule = f.item.result, f.rule
    out = ['<section class="finding">']
    out.append(f"<h3>{_e(f.item.device.name)} · {_e(rule.id)} · {_verdict(f.verdict)}</h3>")
    out.append(f"<p><strong>{_e(rule.title)}</strong><br>")
    out.append(
        f'Advisory: <a href="{_e(f.advisory_url)}">{_e(rule.advisory_id)}</a> · '
        f"{_e(', '.join(rule.cves))}"
    )
    if f.item.kev:
        out.append(f"<br><strong>CISA KEV:</strong> {_e(_kev_text(f))}")
    out.append("</p>")
    out.append(f"<p>Why: {_e(res.reason)}</p>")
    if res.evidence:
        out += ["<p>Evidence:</p>", _pre("\n".join(str(e) for e in res.evidence))]
    if res.runtime_checks:
        out.append("<p>Confirm on the device:</p><ul>")
        out += [
            f"<li><code>{_e(c.command)}</code>: {_e(c.description)}</li>"
            for c in res.runtime_checks
        ]
        out.append("</ul>")
    if f.verdict is Verdict.MITIGATED:
        out.append(f"<p>Mitigation in place: <code>{_e(res.mitigation or '-')}</code>.</p>")
    else:
        out.append(f"<p>Fix: {_e(UPGRADE)}</p>")
        for s in f.snippets():
            out += [f"<p>{_e(s.label)}: {_e(s.description)}</p>", _pre(s.commands)]
    out.append("</section>")
    return out


def report_html(
    results: Sequence[CheckResult], rules: Mapping[str, Rule], meta: ReportMeta | None = None
) -> str:
    meta = meta or ReportMeta()
    totals = Counter(r.result.verdict for r in results)
    devices = _device_rows(results)
    out = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{_e(meta.title)}</title>",
        f"<style>\n{_CSS}\n</style>",
        "</head>",
        "<body>",
        f"<h1>{_e(meta.title)}</h1>",
    ]
    header = [f"Generated: {meta.generated}"] if meta.generated else []
    header += [f"{k}: {v}" for k, v in meta.sources.items()]
    if header:
        out.append(f'<p class="meta">{_e(" · ".join(header))}</p>')

    out += ["<h2>Summary</h2>"]
    out.append(f"<p>{len(devices)} devices, {len({r.result.rule_id for r in results})} rules.</p>")
    out.append('<table><tr><th>Verdict</th><th class="n">Count</th></tr>')
    out += [f'<tr><td>{_verdict(v)}</td><td class="n">{totals[v]}</td></tr>' for v in VERDICT_ORDER]
    out.append("</table>")

    out += ["<h2>Devices</h2>", "<table>"]
    cols = "".join(f'<th class="n">{_e(_short(v))}</th>' for v in VERDICT_ORDER)
    out.append(f"<tr><th>Device</th><th>Platform</th><th>Version</th>{cols}</tr>")
    for row in devices:
        counts = "".join(f'<td class="n">{row.counts[v]}</td>' for v in VERDICT_ORDER)
        out.append(
            f"<tr><td>{_e(row.name)}</td><td>{_e(row.platform)}</td>"
            f"<td>{_e(row.version)}</td>{counts}</tr>"
        )
    out.append("</table>")

    found = findings(results, rules)
    out.append("<h2>Findings</h2>")
    if not found:
        out.append('<p class="muted">No device is affected, indeterminate or mitigated.</p>')
    for f in found:
        out += _finding_html(f)
    out += ["</body>", "</html>"]
    return "\n".join(out) + "\n"
