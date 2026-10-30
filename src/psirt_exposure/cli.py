"""Command-line interface: ``check``, ``watch``, ``mcp``, ``netbox-seed``, ``extract``,
``eval-extraction``, ``eval-golden``."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from psirt_exposure import drift, golden
from psirt_exposure.check import (
    CheckResult,
    CheckSetupError,
    json_item,
    kev_source,
    load_inventory,
    netbox_client,
    run_check,
    select,
    version_source,
)
from psirt_exposure.inventory import Device, load_devices
from psirt_exposure.llm import evaluate
from psirt_exposure.llm.advisory import load_csaf, load_manifest
from psirt_exposure.llm.backends import make_backend
from psirt_exposure.llm.extract import extract_rule, rule_to_yaml
from psirt_exposure.netbox import TOKEN_ENV, URL_ENV, NetBoxError
from psirt_exposure.netbox.seed import seed_netbox
from psirt_exposure.psirt import KevCatalog, VersionSource
from psirt_exposure.report import ReportMeta, report_html, report_markdown
from psirt_exposure.rules import Rule, load_rule, load_rules

__all__ = ["CheckResult", "main", "run_check"]

DEFAULT_MANIFEST = "tests/fixtures/psirt/manifest.yaml"
DEFAULT_ADVISORIES = "tests/fixtures/psirt"
DEFAULT_GOLDEN = "eval/golden/cases.yaml"
DEFAULT_STATE = ".psirt-exposure/watch-state.json"
COLUMNS = ("DEVICE", "PLATFORM", "VERSION", "RULE", "EXPOSURE", "VERDICT", "KEV")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="psirt-exposure", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="match advisory rules against device configs")
    _add_source_args(check)
    check.add_argument("--format", choices=("table", "json", "markdown", "html"), default="table")
    check.add_argument("--evidence", action="store_true", help="print evidence under each row")
    check.add_argument("--output", type=Path, help="write the result to a file instead of stdout")

    watch = sub.add_parser("watch", help="re-run check and report drift against the last run")
    _add_source_args(watch)
    watch.add_argument(
        "--state",
        type=Path,
        default=Path(DEFAULT_STATE),
        help="snapshot of the last run; created on the first run (baseline)",
    )
    watch.add_argument(
        "--interval", type=float, default=0, help="seconds between runs (default 0: run once)"
    )
    watch.add_argument("--count", type=int, help="stop after this many runs (default: no limit)")
    watch.add_argument("--format", choices=("text", "json"), default="text")

    mcp = sub.add_parser("mcp", help="run the MCP server (stdio)")
    mcp.add_argument("--configs", type=Path, default=Path("samples/configs"))
    mcp.add_argument("--rules", type=Path, default=Path("rules"))
    mcp.add_argument("--advisories", type=Path, default=Path(DEFAULT_ADVISORIES))
    mcp.add_argument(
        "--env-file", type=Path, default=Path(".env"), help="dotenv file with API credentials"
    )

    seed = sub.add_parser("netbox-seed", help="load a file-mode inventory into NetBox")
    seed.add_argument("--configs", type=Path, default=Path("samples/configs"))
    seed.add_argument(
        "--env-file",
        type=Path,
        default=Path(".env"),
        help=f"dotenv file with {URL_ENV} / {TOKEN_ENV}",
    )

    extract = sub.add_parser("extract", help="draft rules from advisory text with an LLM")
    extract.add_argument("--manifest", type=Path, default=Path(DEFAULT_MANIFEST))
    extract.add_argument("--key", action="append", help="advisory key (repeatable; default all)")
    extract.add_argument("--csaf", type=Path, help="a single CSAF file (needs one --key)")
    extract.add_argument("--backend", choices=("ollama", "openai"), default="ollama")
    extract.add_argument("--model", help="model name (default: Foundation-Sec-8B on Ollama)")
    extract.add_argument("--base-url", help="backend URL (Ollama host or OpenAI-compatible /v1)")
    extract.add_argument("--attempts", type=int, default=3, help="tries per advisory")
    extract.add_argument("--out", type=Path, help="output dir (default eval/<model>/rules)")

    ev = sub.add_parser("eval-extraction", help="score draft rules against labels and hand rules")
    ev.add_argument("--drafts", type=Path, required=True, help="directory of draft rule YAML")
    ev.add_argument("--rules", type=Path, default=Path("rules"))
    ev.add_argument("--configs", type=Path, default=Path("samples/configs"))
    ev.add_argument("--labels", type=Path, default=Path("samples/configs/labels.yaml"))
    ev.add_argument("--out", type=Path, help="report dir (default: parent of --drafts)")

    gold = sub.add_parser("eval-golden", help="score final verdicts on the golden eval set")
    gold.add_argument("--cases", type=Path, default=Path(DEFAULT_GOLDEN))
    gold.add_argument("--rules", type=Path, default=Path("rules"), help="rules or LLM drafts")
    gold.add_argument("--advisories", type=Path, default=Path(DEFAULT_ADVISORIES))
    gold.add_argument("--out", type=Path, help="report dir (default: directory of --cases)")
    gold.add_argument(
        "--min-accuracy",
        type=float,
        default=0.0,
        help="exit 1 if verdict accuracy is below this (0-1)",
    )
    return parser


def _add_source_args(p: argparse.ArgumentParser) -> None:
    """Inventory, rule and advisory source options shared by ``check`` and ``watch``."""
    p.add_argument(
        "--offline",
        action="store_true",
        help="no network: versions from local CSAF files, KEV only from a local --kev file",
    )
    p.add_argument(
        "--versions",
        choices=("openvuln", "csaf", "none"),
        help="version source (default: openvuln, or csaf with --offline)",
    )
    p.add_argument(
        "--advisories",
        type=Path,
        default=Path(DEFAULT_ADVISORIES),
        help="directory of CSAF files for --versions csaf",
    )
    p.add_argument(
        "--kev",
        help="'cisa' (download the feed), 'none', or a local KEV JSON file "
        "(default: cisa, or none with --offline)",
    )
    p.add_argument(
        "--env-file", type=Path, default=Path(".env"), help="dotenv file with API credentials"
    )
    p.add_argument("--configs", type=Path, default=Path("samples/configs"))
    p.add_argument(
        "--netbox",
        action="store_true",
        help=f"read devices from NetBox ({URL_ENV} / {TOKEN_ENV}) instead of --configs; "
        "allowed with --offline, which only concerns advisory and KEV sources",
    )
    p.add_argument(
        "--netbox-filter",
        action="append",
        metavar="KEY=VALUE",
        help="NetBox device query parameter, e.g. site=psirt-lab (repeatable)",
    )
    p.add_argument("--rules", type=Path, default=Path("rules"))
    p.add_argument("--device", action="append", help="limit to a device (repeatable)")
    p.add_argument("--rule", action="append", help="limit to a rule id (repeatable)")


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _select(items: dict[str, Any], wanted: list[str] | None, what: str) -> list[Any]:
    try:
        return select(items, wanted, what)
    except CheckSetupError as exc:
        raise SystemExit(f"error: {exc}") from None


def _row(item: CheckResult) -> tuple[str, ...]:
    device, result = item.device, item.result
    return (
        device.name,
        device.facts.pid if device.facts else "-",
        device.facts.version if device.facts else "-",
        result.rule_id,
        result.exposure.value if result.exposure else "-",
        result.verdict.value,
        "yes" if item.kev else "-",
    )


def format_table(results: Sequence[CheckResult], evidence: bool) -> str:
    rows = [_row(r) for r in results]
    widths = [max(len(c), *(len(row[i]) for row in rows)) for i, c in enumerate(COLUMNS)]
    out = ["  ".join(c.ljust(w) for c, w in zip(COLUMNS, widths, strict=True)).rstrip()]
    for row, item in zip(rows, results, strict=True):
        out.append("  ".join(c.ljust(w) for c, w in zip(row, widths, strict=True)).rstrip())
        if evidence:
            out.append(f"    reason: {item.result.reason}")
            out.extend(f"    {e}" for e in item.result.evidence)
            out.extend(f"    KEV: {k.cve} added {k.date_added}, due {k.due_date}" for k in item.kev)
    return "\n".join(out)


def format_json(results: Sequence[CheckResult]) -> str:
    return json.dumps([json_item(i) for i in results], indent=2)


def cmd_extract(args: argparse.Namespace) -> int:
    if args.csaf:
        if not args.key or len(args.key) != 1:
            raise SystemExit("error: --csaf needs exactly one --key")
        sources = {args.key[0]: args.csaf}
    else:
        sources = _select_map(load_manifest(args.manifest), args.key, "advisory key")
    backend = make_backend(args.backend, args.model, args.base_url)
    out: Path = args.out or Path("eval") / slug(backend.name) / "rules"
    out.mkdir(parents=True, exist_ok=True)
    entries: dict[str, object] = {}
    failed = 0
    for key, path in sources.items():
        print(f"{key}: extracting with {backend.name} ...", file=sys.stderr, flush=True)
        result = extract_rule(key, load_csaf(path), backend, max_attempts=args.attempts)
        target = out / f"{key}.yaml"
        if result.rule is not None:
            target.write_text(rule_to_yaml(result.rule), encoding="utf-8")
            status = f"ok after {result.attempts} attempt(s) -> {target}"
        else:
            target.unlink(missing_ok=True)
            failed += 1
            status = f"FAILED after {result.attempts} attempt(s): {result.errors[-1:]}"
        print(f"{key}: {status}", file=sys.stderr)
        entries[key] = {
            "valid": result.rule is not None,
            "attempts": result.attempts,
            "errors": result.errors,
            "replies": result.raw,
        }
    log = {"backend": backend.name, "advisories": entries}
    (out / "extraction.json").write_text(json.dumps(log, indent=2) + "\n", encoding="utf-8")
    return 1 if failed else 0


def cmd_eval(args: argparse.Namespace) -> int:
    labels = evaluate.load_labels(args.labels)
    devices = [d for d in load_devices(args.configs) if d.name in labels]
    hand = load_rules(args.rules)
    keys = sorted(hand)
    drafts = {k: load_rule(p) for k in keys if (p := args.drafts / f"{k}.yaml").is_file()}
    meta: dict[str, str] = {"drafts": str(args.drafts)}
    attempts: dict[str, int] = {}
    log_file = args.drafts / "extraction.json"
    if log_file.is_file():
        log = json.loads(log_file.read_text(encoding="utf-8"))
        meta["backend"] = log["backend"]
        attempts = {k: v["attempts"] for k, v in log["advisories"].items()}
    meta["devices"] = str(len(devices))
    scores = evaluate.score(keys, hand, drafts, devices, labels, attempts)
    out: Path = args.out or args.drafts.parent
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.md").write_text(evaluate.report_markdown(scores, meta), encoding="utf-8")
    (out / "report.json").write_text(evaluate.report_json(scores, meta), encoding="utf-8")
    s = evaluate.summary(scores)
    print(
        f"valid {s['valid']}/{s['rules']}, exact {s['exact_rules']}/{s['rules']}, "
        f"cells {s['draft_correct']}/{s['cells']} -> {out / 'report.md'}"
    )
    return 0


def _select_map(items: dict[str, Path], wanted: list[str] | None, what: str) -> dict[str, Path]:
    return dict(zip(wanted or items, _select(items, wanted, what), strict=True))


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "extract":
        return cmd_extract(args)
    if args.command == "eval-extraction":
        return cmd_eval(args)
    if args.command == "eval-golden":
        return cmd_eval_golden(args)
    if args.command == "watch":
        return cmd_watch(args)
    if args.command == "netbox-seed":
        return cmd_netbox_seed(args)
    if args.command == "mcp":
        return cmd_mcp(args)
    return cmd_check(args)


def _netbox_filters(pairs: list[str] | None) -> dict[str, list[str]]:
    filters: dict[str, list[str]] = {}
    for pair in pairs or []:
        key, sep, value = pair.partition("=")
        if not sep or not key:
            raise CheckSetupError(f"--netbox-filter {pair!r} is not KEY=VALUE")
        filters.setdefault(key, []).append(value)
    return filters


def cmd_netbox_seed(args: argparse.Namespace) -> int:
    try:
        count = seed_netbox(netbox_client(args.env_file), args.configs)
    except (CheckSetupError, NetBoxError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"seeded {count} devices from {args.configs}")
    return 0


def _sources(args: argparse.Namespace) -> dict[str, str]:
    inventory = "NetBox" if args.netbox else f"files ({args.configs})"
    versions = args.versions or ("csaf" if args.offline else "openvuln")
    return {"Inventory": inventory, "Versions": versions, "KEV": _kev_kind(args)}


def _kev_kind(args: argparse.Namespace) -> str:
    return str(args.kev or ("none" if args.offline else "cisa"))


def _load_check(
    args: argparse.Namespace,
) -> tuple[list[Device], list[Rule], dict[str, Rule], VersionSource | None, KevCatalog | None]:
    """Selected devices and rules, all rules, version and KEV sources (CheckSetupError)."""
    all_rules = load_rules(args.rules)
    rules = _select(all_rules, args.rule, "rule")
    all_devices = load_inventory(
        netbox=args.netbox,
        configs=args.configs,
        env_file=args.env_file,
        netbox_filters=_netbox_filters(args.netbox_filter),
    )
    versions = version_source(
        args.versions or ("csaf" if args.offline else "openvuln"),
        offline=args.offline,
        advisories=args.advisories,
        env_file=args.env_file,
    )
    kev = kev_source(_kev_kind(args), offline=args.offline)
    devices = _select({d.name: d for d in all_devices}, args.device, "device")
    return devices, rules, all_rules, versions, kev


def cmd_check(args: argparse.Namespace) -> int:
    try:
        devices, rules, all_rules, versions, kev = _load_check(args)
    except CheckSetupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    results = run_check(devices, rules, versions, kev)
    if args.format in ("markdown", "html"):
        meta = ReportMeta(generated=dt.date.today().isoformat(), sources=_sources(args))
        render = report_markdown if args.format == "markdown" else report_html
        text = render(results, all_rules, meta)
    elif args.format == "json":
        text = format_json(results) + "\n"
    else:
        text = format_table(results, args.evidence) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


def _now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")


def cmd_watch(args: argparse.Namespace) -> int:
    """Exit 0 without drift, 1 if any run found drift, 2 on a setup or state error."""
    drifted = False
    runs = 0
    while True:
        try:
            old = drift.load_snapshot(args.state)
            # Reload everything each run: configs, advisory data and KEV can all change.
            devices, rules, _, versions, kev = _load_check(args)
        except (CheckSetupError, drift.DriftError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        new = drift.snapshot(run_check(devices, rules, versions, kev), _now())
        if old is None:
            count = len(new["results"])
            print(f"{new['taken']} baseline saved to {args.state} ({count} results)", flush=True)
        else:
            changes = drift.diff(old, new)
            drifted = drifted or bool(changes)
            if args.format == "json":
                print(drift.changes_json(changes, old["taken"], new["taken"]), flush=True)
            else:
                print(f"{new['taken']} {len(changes)} change(s) since {old['taken']}")
                for c in changes:
                    print(f"  {c}")
                sys.stdout.flush()
        drift.save_snapshot(args.state, new)
        runs += 1
        if args.interval <= 0 or (args.count is not None and runs >= args.count):
            return 1 if drifted else 0
        time.sleep(args.interval)


def cmd_eval_golden(args: argparse.Namespace) -> int:
    try:
        device_dir, cases = golden.load_cases(args.cases)
        devices = {d.name: d for d in load_devices(device_dir)}
        versions = version_source("csaf", offline=True, advisories=args.advisories, env_file=Path())
        scored = golden.score_cases(cases, devices, load_rules(args.rules), versions)
    except (golden.GoldenError, CheckSetupError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    meta = {"cases": str(args.cases), "rules": str(args.rules), "versions": "csaf (offline)"}
    out: Path = args.out or args.cases.parent
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.md").write_text(golden.report_markdown(scored, meta), encoding="utf-8")
    (out / "report.json").write_text(golden.report_json(scored, meta), encoding="utf-8")
    m = golden.metrics(scored)
    precision = golden.fmt_ratio(m["affected_precision"])
    recall = golden.fmt_ratio(m["affected_recall"])
    print(
        f"verdicts {m['verdict_correct']}/{m['cases']}, exposure "
        f"{m['exposure_correct']}/{m['cases']}, AFFECTED precision {precision} recall {recall} "
        f"-> {out / 'report.md'}"
    )
    accuracy = m["verdict_accuracy"] or 0.0
    return 1 if accuracy < args.min_accuracy else 0


def cmd_mcp(args: argparse.Namespace) -> int:
    from psirt_exposure.mcp_server import ServerSettings, build_server

    settings = ServerSettings(
        configs=args.configs, rules=args.rules, advisories=args.advisories, env_file=args.env_file
    )
    build_server(settings).run("stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
