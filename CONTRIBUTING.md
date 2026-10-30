# Contributing

Thanks for helping. The most useful contribution is a new or improved **rule**: one YAML file that
says when a Cisco PSIRT advisory applies to a device configuration. Code changes are welcome too.

## Ground rules

- Everything in the repository is English: code, comments, docs, commit messages, CLI output.
- **No real data, ever.** Configs, `show version` output, fixtures and reports use documentation IP
  ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), `example.*` domains and fake
  hostnames, passwords, password hashes, SNMP communities, keys and serial numbers (for example
  `EXAMPLE-RO`, `FOCFAKE0001`). Never paste a production config, even a "sanitized" one; write a
  minimal config by hand instead.
- Never commit credentials. `.env` is gitignored; `.env.example` lists the variable names only.
  Recorded API responses must not contain OAuth tokens or `Authorization` headers.
- Matching stays deterministic. An LLM may *draft* a rule from advisory text; it never decides a
  verdict.
- Tests run offline. Anything that talks to a real API is marked `live` and is opt-in.

## Development setup

```bash
git clone https://github.com/faithere1/psirt-exposure
cd psirt-exposure
uv sync
uv run pytest
```

Before opening a pull request, run the same checks as CI:

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest
gitleaks git --config .gitleaks.toml --redact      # secret scan over the history
```

## Adding a rule

A rule turns the "vulnerable only if..." part of an advisory into conditions on the running config.
The format is defined (and documented in its docstring) in
[`src/psirt_exposure/rules/model.py`](src/psirt_exposure/rules/model.py); the JSON Schema is
[`rules/rule.schema.json`](rules/rule.schema.json). [`rules/webui.yaml`](rules/webui.yaml) is a
short, complete example.

1. **Add the advisory fixture.** Download the public CSAF 2.0 JSON (no credentials needed):
   `https://sec.cloudapps.cisco.com/security/center/contentjson/CiscoSecurityAdvisory/<id>/csaf/<id>.json`
   and save it unmodified as `tests/fixtures/psirt/<id>.json`. Add an entry with a short `key`
   to `tests/fixtures/psirt/manifest.yaml`. Pick advisories whose exposure depends on a configured
   feature; version-only advisories need no rule.
2. **Draft the rule** by hand, or with `uv run psirt-exposure extract` (see the README). LLM drafts
   land in `eval/<model>/rules/` with `status: draft`.
3. **Write `rules/<key>.yaml`.**
   - `exposure`: the feature is configured. Quote the advisory's "Vulnerable Products" /
     "Determine the Device Configuration" section in `summary` and match it, nothing broader.
   - `affected_platforms`: only if the advisory limits the feature to certain PIDs.
   - `mitigations`: the advisory's workaround or mitigation, each with an `id`, a `condition` and,
     if useful, a config `snippet` (`<name>` marks a value to fill in).
   - `remediation`: how to remove the exposure (for example `no ip http server`).
   - `runtime_checks`: facts that a config cannot show (active tunnels, open ports); these give
     `INDETERMINATE` with the exact `show` command, never a guess.
   - Set `status: reviewed` only after a human has checked the rule against the advisory text.
4. **Add tests.** In `tests/test_matcher.py`, add at least one positive and one negative case to
   `CASES` (a test fails if a rule has neither), plus mitigation and platform cases where they
   apply. Use minimal inline configs.
5. **Label the sample devices.** Add the new key to every device in `samples/configs/labels.yaml`
   (`present`, `absent`, `mitigated`, `not_applicable_platform`, with a `note` for anything
   non-obvious). If no sample device exercises the rule, add a small fake config, or extend one.
6. **Golden set (optional but appreciated).** Add held-out cases to `eval/golden/cases.yaml`.
   Golden devices should be written by someone other than the rule author, and never tuned to
   make a rule pass. Regenerate the report with `uv run psirt-exposure eval-golden`.
7. **Run everything** (the CI command above) and open a pull request that links the advisory and
   explains any judgment calls.

If you change `model.py`, regenerate the schema with
`PYTHONPATH=src uv run python -m psirt_exposure.rules` (a test fails if it is stale).

## Reporting a wrong verdict

Open an issue with the advisory ID, the rule key, the expected and actual verdict, and the
**minimal fake config** that reproduces it. Do not attach real configs. Security issues in
psirt-exposure itself go through [SECURITY.md](SECURITY.md), not public issues.

## License

By contributing you agree that your contributions are licensed under the Apache License 2.0.
