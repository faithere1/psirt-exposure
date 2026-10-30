# Progress

Read `CLAUDE.md` for the workflow. One phase per session; this file is the source of truth.
Status: ☐ not started · ◐ in progress · ☑ done

## Phases

| # | Status | Phase | Exit check |
|---|--------|-------|------------|
| 0 | ☑ | Repo skeleton: uv project, ruff/mypy/pytest, CI, LICENSE, README, CLAUDE.md, PROGRESS.md, .env.example, git init | `uv run pytest` green |
| 1 | ☑ | Fixtures: 10 feature-dependent IOS XE advisories (openVuln API if `.env` has credentials, else public advisory pages) in `tests/fixtures/psirt/`; 6–8 sanitized sample configs + `show version` in `samples/configs/` | fixture load test passes |
| 2 | ☑ | Rule DSL (pydantic) + hand-written YAML rules for the 10 advisories in `rules/` | schema validation tests pass |
| 3 | ☑ | IOS XE config parser (ciscoconfparse2) + deterministic matcher with evidence; CLI `check --offline` | pos/neg tests per rule; verdict table matches labels |
| 4 | ☑ | LLM extraction: pluggable backend (Ollama Foundation-Sec-8B-Instruct default, OpenAI-compatible optional), schema-constrained output; compare to hand rules | extraction accuracy report in `eval/` |
| 5 | ☑ | Live PSIRT client (OAuth2 client credentials) + CISA KEV feed + OS-version verdicts | live smoke test (opt-in); offline tests still pass |
| 6 | ☑ | NetBox inventory: docker-compose (netbox-docker) + seed script | `--netbox` verdicts equal file-mode verdicts |
| 7 | ☑ | MCP server (official `mcp` SDK) + Markdown/HTML reports with mitigation snippets | MCP Inspector calls succeed |
| 8 | ☑ | Golden eval set (≥30 advisory×config pairs), scorer, drift `watch` command | metrics table produced |
| 9 | ☑ | DevNet polish: README demo GIF, architecture diagram, CONTRIBUTING (rules), Code Exchange metadata; **pre-publish security audit**: gitleaks over full git history, scan fixtures/samples/reports for real hostnames, IPs, SNMP communities, password hashes, serials and tokens; `pip-audit` on dependencies; SECURITY.md | fresh-clone quickstart works end to end; gitleaks + pip-audit clean |

## Global decisions

- Language: all repo content in English.
- Platform scope: Cisco IOS XE first; keep parser/rule interfaces platform-agnostic for NX-OS/ASA later.
- Inventory: config files first, NetBox second, Catalyst Center later (optional).
- LLM: pluggable backend; default local Foundation-Sec-8B-Instruct via Ollama (configs never leave the host).
- Version affected/fixed status comes from the openVuln OS-version endpoint, not from the LLM.
- Verdicts: `AFFECTED`, `NOT_AFFECTED_FEATURE_DISABLED`, `FIXED_VERSION`, `MITIGATED`, `INDETERMINATE`.
- `[tool.uv] override-dependencies = ["dnspython>=2.9.0"]` works around ciscoconfparse2 0.9.18's
  `dnspython==2.8.0` pin (CVE-2026-114605); remove it once upstream relaxes the pin. pip users
  installing from PyPI would still get 2.8.0.
- Rules are YAML files with status `draft` (LLM output) or `reviewed` (human-approved).
- Tooling: uv, hatchling, ruff, mypy (strict), pytest, GitHub Actions. License: Apache-2.0.
- Secret safety: `.env` is gitignored; no secret may appear in code, fixtures, logs or reports. Before the first push to GitHub (whenever that happens) run gitleaks on the full history. Sample configs must be sanitized (documentation IPs 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24; fake hostnames, passwords and serials).
- Advisory fixtures are raw public CSAF 2.0 JSON (`tests/fixtures/psirt/<id>.json`, listed in
  `manifest.yaml` with a short `key` per advisory). The openVuln client (Phase 5) must also handle
  this format or map its responses onto the same model.
- Advisory `key`s (`webui`, `smart-install`, `snmp`, `cip`, `ikev1`, `ikev2`, `iox`, `l2tp`,
  `nat-dns-alg`, `dhcp-snooping`) are the shared IDs for rules, labels and eval.
- Sample devices live in `samples/configs/<hostname>/{running-config,show-version}.txt`.
  `samples/configs/labels.yaml` holds config-level exposure labels: `present`, `absent`,
  `mitigated`, `not_applicable_platform`; final verdicts combine these with the version check.
- pytest uses `pythonpath = ["src"]`: on this Mac the editable-install `.pth` gets the macOS
  `hidden` flag and Python 3.14 skips hidden `.pth` files.
- `.gitleaks.toml` extends the default rules; allowlist entries must be narrow (exact public values).
- Rule DSL (`src/psirt_exposure/rules/model.py`, docstring is the spec): one YAML file per advisory
  key in `rules/<key>.yaml`. Config-level verdict order: `exposure` false -> `absent`;
  `affected_platforms` set and PID unmatched -> `not_applicable_platform`; any mitigation true ->
  `mitigated`; else `present`. Condition kinds: `all_of`, `any_of`, `not`, `line` (global lines),
  `block` (parent + descendants, `has`/`lacks`/`where`), `each` (for-all over global lines),
  `platform`, `vlan_coverage`. Patterns use `re.search` on whitespace-stripped line text;
  `{name}` placeholders are bound by named groups in `block.parent` / `each.capture` and
  substituted `re.escape`-d.
- `platform` inside `exposure` means "the feature cannot exist here" (result `absent`, e.g. Smart
  Install on routers); `affected_platforms` means "feature on, platform not listed". The matcher
  needs the PID from `show version` (`cisco <PID> ... processor`).
- Runtime-only facts (active L2TP tunnels, UDP 500 open, IOx CAF running) are `runtime_checks`,
  never conditions. DHCP snooping coverage counts VLAN 1 as configured.
- `rules/rule.schema.json` is the committed JSON Schema of a rule (Phase 4 uses it for
  schema-constrained LLM output); regenerate with `PYTHONPATH=src uv run python -m psirt_exposure.rules`
  (a test fails if it is stale).
- Matcher API (`src/psirt_exposure/matcher.py`): `config_exposure(rule, config, facts)` gives the
  config-level label; `check_rule(rule, config, facts, version_affected)` gives the final verdict.
  `version_affected` is `True`/`False` from the openVuln OS-version data (Phase 5) or `None`
  (offline): a `present` feature then maps to `AFFECTED` / `FIXED_VERSION` / `INDETERMINATE`;
  `absent` and `not_applicable_platform` map to `NOT_AFFECTED_FEATURE_DISABLED`; `mitigated` to
  `MITIGATED`. A rule that needs the PID with no `show version` gives `INDETERMINATE`.
- Parsing is behind a platform-agnostic `DeviceConfig` / `ConfigLine` tree
  (`src/psirt_exposure/config/`); ciscoconfparse2 is only used inside `parse_config`. Comment (`!`)
  and blank lines are dropped; line numbers are 1-based file lines.
- Evidence lines are redacted at creation (`src/psirt_exposure/redact.py`); reports and the MCP
  server must use `Evidence.text` and never print raw config lines.
- File-mode inventory: `psirt_exposure.inventory.load_devices(dir)`; NetBox (Phase 6) must return
  the same `Device` objects. CLI entry point `psirt-exposure` (`src/psirt_exposure/cli.py`); without
  `--offline` it exits 2 until Phase 5.
- LLM extraction (`src/psirt_exposure/llm/`): the model writes only `ExtractedRule` (summary,
  exposure, affected_platforms, mitigations, runtime_checks); ids/CVEs/title come from the CSAF
  and status is always `draft`. Backends: `ollama` (default model `foundation-sec-8b-instruct`,
  created from `ollama/foundation-sec-8b-instruct.Modelfile`; the HF GGUF lacks a chat template)
  and `openai` (any OpenAI-compatible `/chat/completions`, key from `OPENAI_API_KEY`). Replies are
  constrained by `bounded_schema()` (condition union unrolled to depth 4, no `$ref` cycles, no
  `pattern` keyword: it crashes Ollama 0.15) and validated by pydantic, retried with the errors.
- Drafts live in `eval/<backend-model>/rules/`, never in `rules/`; `check` must not use drafts.
- Advisory data sources live in `src/psirt_exposure/psirt/`: `OpenVulnClient` (token from
  `https://id.cisco.com/oauth2/default/v1/token`, API `https://apix.cisco.com/security/advisories/v2`,
  `OSType/iosxe?version=`; `NO_DATA_FOUND` = no advisories; 401 refreshes once, 429/503 retried),
  KEV (`fetch_kev` / `load_kev`), and `VersionSource`s giving `version_affected` for `check_rule`:
  `OpenVulnVersionSource` (one request per distinct version) and `CsafVersionSource` (offline,
  CSAF `known_affected` in the "Cisco IOS XE Software" family). Versions are normalized
  (`17.09.03a` -> `17.9.3a`) before lookup or comparison.
- CSAF "not listed" is not "fixed": an unlisted version is `False` only if its release train is
  listed or newer than every listed train; an older unlisted train (EoL, not evaluated) is `None`.
- `check` sources: `--versions openvuln|csaf|none` (default openvuln; csaf with `--offline`),
  `--kev cisa|none|FILE` (default cisa; none with `--offline`). Missing credentials or a network
  source under `--offline` exit 2. Credentials come from the environment or `--env-file` (.env);
  the secret/token never appear in messages or `repr`. KEV hits are informational (`KEV` column,
  JSON `kev`), they do not change the verdict. Phase 7 reports should reuse `run_check` /
  `CheckResult` from `cli.py` (move them to a module if needed).
- NetBox inventory (`src/psirt_exposure/netbox/`): PID = device type `part_number` (fallback
  `model`); custom fields `software_version` (text, raw `show version` string) and `running_config`
  (longtext) on `dcim.device`; facts need both PID and version, else `None`; devices without a
  config are skipped with a warning. `load_netbox_devices` returns objects equal to
  `load_devices`. `check --netbox [--netbox-filter K=V]` replaces `--configs`; `--offline` does
  not forbid it (it only governs advisory/KEV sources). `NETBOX_URL` / `NETBOX_TOKEN` from env or
  `.env`; `nbt_` tokens use `Bearer`, others `Token`. Seed: `psirt-exposure netbox-seed` (idempotent,
  site `psirt-lab`, platform `cisco-ios-xe`). Lab: `netbox/docker-compose.yml` (NetBox v4.7,
  netbox-docker 5.1.1, secrets only from `.env`, port 127.0.0.1:8000).
- Live tests are marked `live`, deselected by default (`addopts = "-m 'not live'"`), and run with
  `PSIRT_EXPOSURE_LIVE=1 uv run pytest -m live`.
- Shared check pipeline lives in `src/psirt_exposure/check.py`: `CheckResult`, `run_check`,
  `json_item`, `select`, `version_source`, `kev_source`, `netbox_client`, `load_inventory`,
  `CheckSetupError`. The CLI, reports and MCP server all use it (`cli.py` re-exports
  `run_check` / `CheckResult`).
- Remediation hints in the rule DSL (text only, never evaluated): `mitigations[].snippet`
  (applies that workaround) and rule-level `remediation: {description, snippet}` (config change
  that makes `exposure` false). `<name>` marks operator-filled values. `ExtractedRule` may carry
  them too. Upgrading is always the primary fix in reports.
- Reports (`src/psirt_exposure/report.py`): `report_markdown` / `report_html(results, rules, meta)`,
  deterministic for the same input (caller passes the date); findings = `AFFECTED`,
  `INDETERMINATE`, `MITIGATED`, sorted by that order, then device, rule. HTML is self-contained,
  every value `html.escape`-d, no scripts. CLI: `check --format markdown|html [--output FILE]`.
- MCP server (`src/psirt_exposure/mcp_server.py`, `psirt-exposure mcp`, stdio) uses the `mcp` 2.x
  API (`mcp.server.mcpserver.MCPServer`; FastMCP is gone in 2.x), pinned `mcp>=2.3,<3`. Tools
  `list_devices`, `list_rules`, `check`, `report`; resource `psirt-exposure://rules/{rule_id}`. Tools take
  names only, never paths (paths fixed by `ServerSettings` at start-up); defaults are offline
  (`versions="csaf"`, `kev="none"`, `inventory="files"`). Errors are `ToolError`s. Tool logic is
  in `ExposureTools` (testable without a transport).
- Golden eval set (`eval/golden/cases.yaml` + `eval/golden/devices/`, scorer
  `src/psirt_exposure/golden.py`, CLI `eval-golden`): held-out devices only, never used to tune
  rules; final verdicts use offline CSAF versions; a test fails if `eval/golden/report.md` is
  stale and if reviewed rules miss any case. New tricky cases go here as new devices, not into
  `samples/configs/` (that is the development set). `--min-accuracy` is the CI gate.
- Drift (`src/psirt_exposure/drift.py`, CLI `watch`): snapshot = verdict, exposure, mitigation,
  sorted redacted evidence text (no line numbers), KEV CVEs per `device/rule`; state in
  `.psirt-exposure/watch-state.json` (gitignored); exit 0 no drift / 1 drift / 2 error. `check`
  and `watch` share `_add_source_args` / `_load_check` in `cli.py`.

## Log

### Phase 0 — 2026-10-30
- Done: created the uv project (`pyproject.toml`, `src/netsec_check/`), smoke test, CI workflow,
  Apache-2.0 LICENSE, README, CLAUDE.md (agent rules), PROGRESS.md, `.gitignore`, `.env.example`, git repo.
- Files: `pyproject.toml`, `src/netsec_check/__init__.py`, `tests/test_smoke.py`,
  `.github/workflows/ci.yml`, `README.md`, `CLAUDE.md`, `PROGRESS.md`, `.gitignore`, `.env.example`, `LICENSE`.
- Exit check: ruff, mypy, pytest all green.
- Open: user is registering a Cisco API Console app (openVuln, Client Credentials); they will put
  `CISCO_CLIENT_ID` / `CISCO_CLIENT_SECRET` into `.env` themselves.
- Next step (Phase 1): check whether `.env` has credentials; pick 10 IOS XE advisories whose
  exposure depends on a configured feature (e.g. HTTP server/Web UI, Smart Install, SNMP, IKEv2,
  NAT ALG, DHCP snooping, Telnet/SSH-related); save raw fixtures; write sample configs.

### Phase 1 — 2026-10-30
- Done: no `.env` credentials yet, so the 10 advisories were downloaded as public CSAF 2.0 JSON
  (no auth): Web UI, Smart Install, SNMP (2025), CIP, IKEv1, IKEv2 (2026), IOx, L2TP, NAT DNS ALG,
  DHCP snooping. Rejected: WLC file upload (affected regardless of config), UTD (depends on command
  support, not config). Wrote 8 sanitized IOS XE devices (C8300, ISR4451, ISR1100, C8500L,
  Cat3850, C9200L, IE-3400, C8000V) with `show version`, plus `labels.yaml` (80 labels; every
  advisory has at least one `present` and one `absent` device). Tricky cases included: secure-server
  only, IOx without HTTP, crypto map defined but not applied, DHCP snooping on a non-listed platform,
  SNMP exclusion view, DNS ALG disabled.
- Files: `tests/fixtures/psirt/*.json`, `tests/fixtures/psirt/manifest.yaml`,
  `samples/configs/*/`, `samples/configs/labels.yaml`, `tests/test_fixtures.py`, `.gitleaks.toml`,
  `pyproject.toml` (+pyyaml, +types-PyYAML, pytest `pythonpath`), `uv.lock`.
- Exit check: ruff, ruff format, mypy, pytest all green (39 passed). Tests also check that samples
  use only documentation IPs and fake secrets.
- Open: gitleaks is not installed locally (`brew install gitleaks`), so it has not run yet; the
  webui CSAF contains Cisco's public IOC hash in a curl `Authorization` header (allowlisted).
  Nothing is committed yet. L2TP "active tunnels" and IKE "UDP 500 open" are runtime facts; rules
  can only see the config, so labels treat configured+applied as `present`.
- Next step (Phase 2): pydantic rule DSL + YAML rules in `rules/` for the 10 keys in
  `tests/fixtures/psirt/manifest.yaml`, guided by the notes in `samples/configs/labels.yaml`.


### Phase 2 — 2026-10-30
- Done: pydantic rule DSL (strict, frozen models; one-key discriminated conditions; regex and
  placeholder-scope validation; unique mitigation ids), YAML loader (file name must equal id),
  committed JSON Schema, and 10 rules in `rules/` with summaries, mitigations (webui session
  modules none, SNMP exclusion view per community/group, NAT DNS ALG off) and runtime checks.
  Titles are copied verbatim from the CSAF documents (a test enforces it).
- Files: `src/netsec_check/rules/{__init__,model,loader,__main__}.py`, `rules/*.yaml`,
  `rules/rule.schema.json`, `tests/test_rules_schema.py`, `pyproject.toml` (+pydantic), `uv.lock`.
- Exit check: ruff, ruff format, mypy, pytest all green (108 passed).
- Open: rules are marked `reviewed` but were written by the agent from the advisory text; the
  user should skim them. The Smart Install platform list (WS-C3650/3850/45xx) is conservative.
  Not modelled yet: crypto dynamic maps, G-IKEv2/GET VPN, `ip http access-class` (it reduces
  exposure but is not a mitigation). Nothing is committed yet; gitleaks still not installed.
- Next step (Phase 3): ciscoconfparse2 parser + evaluator for each condition kind (return the
  matching lines as evidence), PID/version extraction from `show version`, CLI `check --offline`,
  and per-rule pos/neg tests that reproduce every label in `samples/configs/labels.yaml`.


### Phase 3 — 2026-10-30
- Done: ciscoconfparse2-backed config parser (line tree with 1-based line numbers), `show version`
  parser (PID, IOS XE version, hostname), deterministic matcher for every condition kind with
  evidence (matching lines, or the lines that broke an `each`), secret redaction of evidence,
  final-verdict mapping, file-mode inventory and CLI `netsec-check check --offline`
  (`--device`, `--rule`, `--format table|json`, `--evidence`). README quick start added.
- Files: `src/netsec_check/{matcher,redact,inventory,cli}.py`,
  `src/netsec_check/config/{__init__,parser,show_version}.py`, `tests/test_config_parser.py`,
  `tests/test_matcher.py`, `tests/test_cli.py`, `pyproject.toml` (+ciscoconfparse2,
  `[project.scripts]`), `uv.lock`, `README.md`.
- Exit check: ruff, ruff format, mypy, pytest all green (271 passed). All 80 labels in
  `samples/configs/labels.yaml` are reproduced; 40 synthetic pos/neg cases cover every rule
  (plus every mitigation and every `affected_platforms` list). Offline table: 57 absent,
  4 mitigated, 1 not_applicable_platform, 18 present (INDETERMINATE until versions are checked).
- Open: on this Mac `uv run netsec-check` can fail with `No module named netsec_check` when the
  editable `.pth` is hidden again; use `PYTHONPATH=src uv run netsec-check ...` or re-run
  `uv sync`. ciscoconfparse2 pulls in many transitive deps (rich, typeguard, ...); revisit in the
  Phase 9 `pip-audit`. Smart Install `present` has only the platform as evidence (default-on
  feature). Nothing is committed yet; gitleaks still not installed.
- Next step (Phase 4): pluggable LLM backend (Ollama Foundation-Sec-8B-Instruct default,
  OpenAI-compatible optional) that turns the CSAF advisory text into a rule constrained by
  `rules/rule.schema.json`; compare extracted rules to `rules/*.yaml` by running both through
  `config_exposure` on the sample devices; write the accuracy report to `eval/`.


### Phase 4 — 2026-10-30
- Done: advisory text loader (CSAF Summary / Vulnerable Products / Not Vulnerable / Workarounds),
  pluggable backends (Ollama, OpenAI-compatible) over httpx, schema-constrained extraction with a
  validation-error retry loop, mitigation-id normalization, YAML dump of drafts, scorer comparing
  drafts and hand rules via `config_exposure` on the 8 sample devices, CLI `extract` and
  `eval-extraction`, README section. Ran Foundation-Sec-1.1-8B-Instruct Q4_K_M locally on all 10
  advisories.
- Files: `src/netsec_check/llm/{__init__,advisory,backends,extract,evaluate}.py`,
  `src/netsec_check/cli.py`, `tests/test_llm.py`, `ollama/foundation-sec-8b-instruct.Modelfile`,
  `eval/README.md`, `eval/ollama-foundation-sec-8b-instruct/{rules/*,report.md,report.json}`,
  `pyproject.toml` (+httpx), `uv.lock`, `README.md`.
- Exit check: ruff, ruff format, mypy, pytest all green (309 passed); report in
  `eval/ollama-foundation-sec-8b-instruct/report.md`. Result: 8/10 schema-valid, 0/10 exact,
  48/80 cells (below the 57/80 always-absent baseline), 0/23 non-absent labels. Drafts are too
  strict: show commands / runtime output as config lines, product names as platform regexes,
  interface commands as global lines. Analysis in `eval/README.md`.
- Open: no comparison model was run (OpenAI-compatible backend untested against a real server).
  Possible improvements: leave-one-out few-shot from reviewed rules, a draft linter (reject
  `^show`, non-PID platform names). Ollama must be running (`ollama serve`) for `extract`.
  Nothing is committed yet; gitleaks still not installed.
- Next step (Phase 5): openVuln OAuth2 client-credentials client (credentials from `.env`),
  OS-version endpoint -> `version_affected` for `check_rule`, CISA KEV feed, live smoke test
  (opt-in); map openVuln responses onto the CSAF-based advisory model.


### Phase 5 — 2026-10-30
- Done: openVuln v2 client (OAuth2 client credentials, token cache with expiry margin, 401
  refresh, 429/503 retry with Retry-After, `NO_DATA_FOUND` handling, advisory by id, public CSAF
  download without the token), `.env` reader, CISA KEV parser/fetcher, version sources (live
  openVuln, offline CSAF with the release-train rule above), CLI `check` live mode with
  `--versions`, `--kev`, `--advisories`, `--env-file`, `KEV` column and JSON `kev` field, README
  live-mode section, trimmed KEV fixture (illustrative values, documented in its README).
- Files: `src/netsec_check/psirt/{__init__,openvuln,kev,versions}.py`, `src/netsec_check/cli.py`,
  `tests/test_psirt.py`, `tests/test_live.py`, `tests/test_cli.py`,
  `tests/fixtures/kev/{known_exploited_vulnerabilities.json,README.md}`, `pyproject.toml`
  (pytest `live` marker), `README.md`.
- Exit check: ruff, ruff format, mypy, pytest all green (342 passed, 4 live deselected).
  `NETSEC_LIVE=1 uv run pytest -m live`: the KEV feed test passed against the real CISA feed; the
  3 openVuln tests were skipped because `.env` has no credentials yet. Offline verdicts on the
  samples: 10 AFFECTED, 58 NOT_AFFECTED_FEATURE_DISABLED, 7 FIXED_VERSION, 4 MITIGATED,
  1 INDETERMINATE (SNMP on access-sw-01: the 16.3 train is not evaluated by the advisory).
- Open: the openVuln live path is untested against the real API. Run
  `NETSEC_LIVE=1 uv run pytest -m live` after filling `.env`; the response shape for
  `OSType/iosxe` and the "no advisories" reply (assumed `errorCode: NO_DATA_FOUND`) are based on
  the API documentation. openVuln and CSAF can disagree for versions Cisco did not evaluate.
  Advisories that openVuln reports for a version but that have no rule are not shown yet.
  Nothing is committed yet; gitleaks still not installed (fake test secrets like
  `fake-client-secret-0000` may need an allowlist entry).
- Next step (Phase 6): netbox-docker compose file + seed script that loads the 8 sample devices
  (platform, version, config context or attached config), and a NetBox inventory that returns the
  same `Device` objects as `load_devices`; `check --netbox` must equal file-mode verdicts.

### Phase 5 addendum — 2026-10-30
- The user registered a Cisco API Console app (Service, Client Credentials, PSIRT openVuln API) and
  filled `.env`. `NETSEC_LIVE=1 uv run pytest -m live`: 4 passed (token, `OSType/iosxe` for
  17.9.3a vs 17.9.4a, advisory by id + CSAF download, KEV feed, CLI live run). The openVuln response
  shapes assumed in Phase 5 are confirmed.
- Open: rate limit is 5 calls/s and 60 calls/min; `get_json` retries a 429 at most 3 times
  (Retry-After or 2/4/8 s), which may not outlast a one-minute window for inventories with more
  than ~60 distinct versions. Add client-side throttling before Phase 6/9. Cisco also offers a
  "Cisco PSIRT OpenVuln-MCP" API; check overlap when designing the Phase 7 MCP server.

### Phase 6 — 2026-10-30
- Done: installed Colima + Docker CLI + docker-compose (Homebrew) and started the Colima VM;
  trimmed netbox-docker compose file (NetBox v4.7, Postgres 18, one Valkey, no worker; every
  secret interpolated from `.env`); lab secret generator (`python -m netsec_check.netbox.secrets`,
  appended to the user's `.env`, values never printed); NetBox REST client (pagination, v1/v2
  tokens, token never in messages/repr); NetBox inventory; idempotent seed script; CLI
  `check --netbox`, `--netbox-filter`, `netbox-seed`; README section; `.env.example` entries.
- Files: `netbox/docker-compose.yml`, `src/netsec_check/netbox/{__init__,client,inventory,seed,
  secrets}.py`, `src/netsec_check/cli.py`, `tests/test_netbox.py`, `tests/test_live.py`,
  `README.md`, `.env.example`.
- Exit check: ruff, ruff format, mypy, pytest all green (360 passed, 5 live deselected).
  Against the real local NetBox: seeded 8 devices (re-run creates nothing), and
  `check --offline --format json` with `--netbox` is byte-identical to file mode;
  `NETSEC_LIVE=1 uv run pytest -m live`: 5 passed (incl. the new NetBox equality test).
- Open: `docker compose` (plugin form) is not registered with the Docker CLI on this Mac; use
  `docker-compose ...` or add `"cliPluginsExtraDirs": ["/opt/homebrew/lib/docker/cli-plugins"]` to
  `~/.docker/config.json`. The NetBox containers keep running (`docker-compose --env-file .env -f
  netbox/docker-compose.yml down` to stop; `colima stop` for the VM). openVuln client-side
  throttling (Phase 5 addendum) is still not done. Nothing is committed yet; gitleaks still not
  installed (the compose file holds no secrets, only `${VAR:?}` references).
- Next step (Phase 7): MCP server with the official `mcp` SDK exposing check/inventory tools
  (reuse `run_check`/`CheckResult`, file or NetBox inventory), Markdown/HTML reports with
  mitigation snippets using redacted `Evidence.text`; verify with MCP Inspector.

### Phase 7 — 2026-10-30 (◐)
- Done: moved the check pipeline out of `cli.py` into `check.py`; DSL remediation hints
  (`Mitigation.snippet`, `Rule.remediation`) and snippets in 7 rules (webui, snmp, nat-dns-alg
  workarounds; webui, smart-install, cip, iox, dhcp-snooping remediation; ikev1/ikev2/l2tp have
  none because the feature is the service); schema regenerated; Markdown/HTML report renderer;
  CLI `--format markdown|html`, `--output`, `mcp` subcommand; MCP server with 4 tools + 1
  resource template; README "Reports" and "MCP server" sections (client config, Inspector usage).
- Files: `src/netsec_check/{check,report,mcp_server}.py`, `src/netsec_check/cli.py`,
  `src/netsec_check/rules/{model,__init__}.py`, `src/netsec_check/llm/extract.py`, `rules/*.yaml`,
  `rules/rule.schema.json`, `tests/test_report.py`, `tests/test_mcp_server.py`,
  `tests/test_llm.py`, `tests/test_netbox.py` (monkeypatch target moved to
  `netsec_check.check.netbox_from_env`), `pyproject.toml` (+mcp), `uv.lock`, `README.md`.
- Exit check: ruff, ruff format, mypy, pytest all green (382 passed, 5 live deselected). MCP calls
  verified with the SDK client in-process and against the real `netsec-check mcp` subprocess over
  stdio (`test_stdio_subprocess`: tools/list, `check`, `report`); MCP `check` output equals CLI
  `--format json`; reports contain no sample secrets. **MCP Inspector itself was not run**: the
  agent's `npx @modelcontextprotocol/inspector` download was blocked by the permission classifier.
- Resume point: run (user or agent with permission)
  `npx @modelcontextprotocol/inspector --cli uv run --directory "$PWD" netsec-check mcp --method tools/list`
  and `... --method tools/call --tool-name check --tool-arg only_findings=true`; if both succeed,
  append a short addendum and set Phase 7 to ☑. No code changes are expected.
- Open: Cisco's "PSIRT OpenVuln-MCP" API was not evaluated; netsec-check's server is
  complementary (config-level exposure with evidence, not advisory lookup). openVuln client-side
  throttling (Phase 5 addendum) is still not done. Only stdio transport is exposed. Nothing is
  committed yet; gitleaks still not installed.
- Next step (Phase 8, after the Inspector check): golden eval set (≥30 advisory×config pairs),
  scorer, drift `watch` command.

### Phase 7 addendum — 2026-10-30
- MCP Inspector exit check run by the user (`npx @modelcontextprotocol/inspector@latest --cli -e
  PYTHONPATH=$PWD/src uv run --directory $PWD netsec-check mcp ...`): `tools/list` returned the 4
  tools with schemas and annotations; `tools/call check only_findings=true` returned
  `isError: false` with 10 AFFECTED, 1 INDETERMINATE, 4 MITIGATED (same as the CLI). Phase 7 ☑.
- Notes: the agent's first attempt failed only because its `2>&1 | json.load` pipe also caught
  uv's "Building netsec-check" lines. The Inspector CLI prints evidence as `&lt;redacted&gt;`;
  the server sends `<redacted>` (checked over stdio with the SDK client), so this is Inspector
  display escaping, not a server bug.
- Next step (Phase 8): golden eval set (≥30 advisory×config pairs), scorer, drift `watch` command.

### Phase 8 — 2026-10-30
- Done: 6 held-out golden devices (C8200, ISR4331, WS-C3650, IE-3300, C8000V, one config-only
  device without `show version`) and 60 labeled advisory×config pairs covering all 5 verdicts;
  scorer with verdict/exposure accuracy, per-verdict precision/recall/F1, AFFECTED
  precision/recall, per-rule accuracy, confusion matrix and mismatch list (Markdown + JSON,
  deterministic); CLI `eval-golden` (`--rules` also scores LLM drafts, `--min-accuracy` gate);
  drift snapshots/diff and CLI `watch` (`--state`, `--interval`, `--count`, `--format
  text|json`); refactored `check` source options into shared helpers; README "Drift watch" and
  "Evaluation" sections; `eval/README.md` Phase 8 section with the metrics table.
- Files: `src/netsec_check/{golden,drift}.py`, `src/netsec_check/cli.py`,
  `eval/golden/{cases.yaml,report.md,report.json,devices/*}`,
  `eval/ollama-foundation-sec-8b-instruct/golden/report.{md,json}`, `tests/test_golden.py`,
  `tests/test_drift.py`, `eval/README.md`, `README.md`, `.gitignore`.
- Exit check: ruff, ruff format, mypy, pytest all green (405 passed, 5 deselected). Metrics
  table: `eval/golden/report.md`. Reviewed rules 60/60 verdicts and exposure (AFFECTED
  precision/recall 1.00); Foundation-Sec-8B drafts 32/60 verdicts, 0/10 AFFECTED recall, below
  the always-not-affected baseline (38/60). `watch` demo on a copy of the samples: baseline,
  0 changes, then a new SNMP community gave `verdict edge-rtr-02 snmp: MITIGATED -> AFFECTED`
  (exit 1).
- Open: golden labels were written by the agent that wrote the rules, so 60/60 is an upper
  bound; the user (or another reviewer) should skim `eval/golden/cases.yaml` and ideally add
  independently labeled devices. `watch` only covers rules in `rules/`; openVuln advisories
  without a rule are still not reported. openVuln client-side throttling (Phase 5 addendum) is
  still not done and matters for long `watch --interval` runs with live sources. Nothing is
  committed yet; gitleaks still not installed.
- Next step (Phase 9): DevNet polish (README demo GIF, architecture diagram, CONTRIBUTING for
  rules, Code Exchange metadata) and the pre-publish security audit (gitleaks over the full
  history, scan fixtures/samples/eval devices/reports, `pip-audit`, SECURITY.md); fresh-clone
  quickstart end to end.

### Phase 8 addendum — 2026-10-30
- Correction: gitleaks **is** installed (8.30.1, `/opt/homebrew/bin/gitleaks`); the "gitleaks still
  not installed" notes in the Phase 2–8 entries were carried forward without re-checking.
- Working-tree scan (`gitleaks dir . --config .gitleaks.toml --redact`, no commits exist yet, so
  no history scan is possible): 8 findings, all `generic-api-key` in `.env`, which is gitignored
  (`git check-ignore` confirms) and holds the real credentials by design. No findings in code,
  fixtures, samples, `eval/golden/devices` or reports.
- Phase 9 still has to run `gitleaks git` over the full history after the first commit and
  before any push.

### Phase 9 — 2026-10-30
- Done: README demo GIF (`docs/demo.gif`, rendered from real offline CLI runs on a temp copy of the
  sample data by `scripts/demo_gif.py`; `uv run --with pillow python scripts/demo_gif.py`),
  Mermaid architecture diagram, fresh-clone quick start, Limitations / Contributing / Credits
  sections, CI and license badges; `CONTRIBUTING.md` (ground rules, step-by-step rule workflow);
  `SECURITY.md` (private reporting via GitHub, data handling, hygiene); Code Exchange metadata and
  submission checklist in `docs/code-exchange.md` (Code Exchange takes metadata through its web
  form, no repo file format is required).
- Security audit: `pip-audit` found dnspython 2.8.0 (CVE-2026-114605, transitive via
  ciscoconfparse2's exact pin); fixed with a uv override to 2.9.1 (see Global decisions), re-audit
  clean. Manual scan of all tracked files: only documentation IPs (other dotted quads are
  software versions in public CSAF text), `example.*` domains, `EXAMPLE*` communities,
  `NotARealHash` hashes, `*FAKE*` serials; the only `Authorization` value is the public Talos
  implant check quoted in the webui advisory (already allowlisted). `gitleaks dir`: findings only
  in the gitignored `.env`.
- Initial commit `201aaf7` on `main` (user approved; not pushed). `gitleaks git` over the full
  history: 1 commit, no leaks.
- Exit check: ruff, ruff format, mypy, pytest green (405 passed, 5 deselected). Fresh clone into
  a temp dir: `uv sync`, `check --offline --evidence`, `--format json`, `--format html`,
  `eval-golden` (60/60) and pytest all work without the `PYTHONPATH` workaround.
- Notes: in the Desktop checkout the editable `.pth` was hidden again (iCloud also left a
  dataless `_editable_impl_netsec_check 2.pth` in `.venv`); the Desktop folder is iCloud-synced,
  which is the likely cause. Fresh clones elsewhere are not affected.
- Open: GitHub URL `https://github.com/faithere1/netsec-check-mcp` is assumed in README,
  CONTRIBUTING, SECURITY and `docs/code-exchange.md`; fix it if the repo name differs. Enable
  private vulnerability reporting in the GitHub repo settings after creating it. Re-run
  `gitleaks git` immediately before the first push (this PROGRESS entry and any later changes are
  not committed yet). Carried over: independent golden labels, openVuln throttling, advisories
  without a rule are not reported. Optional: gitleaks + pip-audit as CI jobs.
- All phases in the table are ☑.

### Rename to psirt-exposure — 2026-10-30
- Project renamed from `netsec-check` to `psirt-exposure` (name checked free on PyPI and GitHub):
  package `src/psirt_exposure/`, CLI `psirt-exposure`, repo URL
  `https://github.com/faithere1/psirt-exposure`, MCP resource `psirt-exposure://rules/{rule_id}`,
  MCP tools class `ExposureTools`, watch state `.psirt-exposure/`, live-test switch
  `PSIRT_EXPOSURE_LIVE=1`, NetBox lab site `psirt-lab`, compose project `psirt-exposure-netbox`.
  Global decisions and CLAUDE.md updated; earlier log entries keep the old names.
- Regenerated `docs/demo.gif`, rule schema and golden report (unchanged, 60/60).
- Exit check: ruff, ruff format, mypy, pytest green (405 passed, 5 deselected); fresh copy of the
  working tree: `uv sync`, `check --offline`, pytest OK. `gitleaks dir`: findings only in `.env`.
- Notes: an existing local NetBox lab still runs under the old compose project `netsec-netbox`
  with site `netsec-lab`; bring it down (`docker compose -p netsec-netbox down -v`) and re-run
  `up` + `psirt-exposure netbox-seed`. MCP client configs must use `psirt-exposure mcp`. The local
  folder is still named `netsec-check-mcp` (renaming it is optional).
- Open: rename not committed yet; re-run `gitleaks git` before the first push.

### Pre-submission secret scan — 2026-10-30
- Scope: full git history (1 commit) and the 132 files that would be committed (uncommitted rename
  included). Engines: gitleaks 8.30.1 with the project config and with default rules only (no
  allowlist), detect-secrets (via uvx); every real value in `.env` (20 values, incl. token parts)
  searched in files, history and commit metadata; custom patterns (AWS, OpenAI/Anthropic, GitHub,
  Slack, Google, Hugging Face, JWT, private keys, NetBox `nbt_` tokens, Bearer/Token headers,
  credentials in URLs); 32+ char hex/base64 strings; local paths and personal names.
- Result: no secrets. gitleaks 0 findings (both configs); `.env` values found nowhere; detect-secrets
  4 false positives (public Talos IOC in `.gitleaks.toml`, the `CISCO_CLIENT_SECRET` env var
  name, `fake-*` / `test-key-not-real` test strings). Config secrets are all `EXAMPLE-*` /
  `NotARealHash*`. `docs/demo.gif` holds only rendered fake sample output and no metadata.
  No sensitive filenames ever committed; no unreachable objects; CI uses no secrets.
- Hardened `.gitignore`: `.env.*` (except `.env.example`), `*.pem`, `*.key`, old `.netsec-check/`
  state dir, and `/report.*` (root-level reports can contain real device data).
- Note: commit `201aaf7` carries the author email from the local git config; it becomes public on
  push. Re-run `gitleaks git` right before the first push.

### Code Exchange alignment — 2026-10-30
- Rename + `.gitignore` hardening committed as `4468ace` (user approved); `gitleaks git` over both
  commits: no leaks.
- Checked the official requirements (Code Exchange About page: Cisco-relevant, public on GitHub,
  OSI license, clear docs; scored 1-10 automatically) and Cisco's repo template
  (`CiscoDevNet/code-exchange-repo-template/manual-sample-repo`). Details and the remaining
  checklist are in `docs/code-exchange.md`.
- README restructured into the template's section order: descriptive title, description,
  technology stack/status, demo GIF, Use Case (+ architecture), Installation (uv on
  macOS/Linux/Windows; Windows untested), Configuration (env var table with formats, file-mode
  layout), Usage (subsections), Related Sandbox (save `show` output from a DevNet IOS XE sandbox,
  outside the repo), Known issues, Getting help, Getting involved, Credits and references,
  Licensing info. Two claims corrected: verdicts cite config lines + reason + advisory link (not
  "the advisory sentence"); without `show-version.txt` only enabled features become INDETERMINATE.
- Added `NOTICE` (Copyright 2026 faithere1, per the user; attributions for netbox-docker, Cisco
  CSAF fixtures, KEV sample, Foundation-Sec chat template), `CODE_OF_CONDUCT.md` (Contributor
  Covenant 2.1 verbatim; contact = maintainer via GitHub private reporting, no email, per the
  user), issue forms (`wrong-verdict`, `bug-report`, contact links), CI `security` job
  (gitleaks full history + pip-audit). Workflow and issue forms validated against their JSON
  schemas.
- Checks: ruff, ruff format, mypy, pytest green (405 passed); fresh copy OK; gitleaks (default and
  project config) no leaks; detect-secrets only the known false positives.
- Open: these changes are not committed yet. After pushing: set repo description/topics, enable
  private vulnerability reporting, confirm both CI jobs are green (Windows still untested), then
  submit.
