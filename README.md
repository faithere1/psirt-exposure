# psirt-exposure: am I actually affected by a Cisco PSIRT advisory?

**psirt-exposure** matches Cisco PSIRT security advisories against your real IOS XE device
configurations and gives one verdict per device and advisory, with the config lines as evidence.
It runs as a CLI and as an MCP server for AI assistants.

[![CI](https://github.com/faithere1/psirt-exposure/actions/workflows/ci.yml/badge.svg)](https://github.com/faithere1/psirt-exposure/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

![psirt-exposure demo: offline check with evidence, then drift watch](docs/demo.gif)

- **Technology stack:** Python 3.11+ (standalone CLI and MCP server), uv, ciscoconfparse2,
  Cisco PSIRT openVuln API, CISA KEV, NetBox (optional), Ollama with Foundation-Sec-8B (optional).
- **Status:** pre-1.0 (alpha). Cisco IOS XE only, 10 reviewed rules. All sample data in this
  repository is fake.

## Use Case

The Cisco PSIRT openVuln API tells you which software versions an advisory affects and which are
fixed. It does not tell you whether the vulnerable *feature* is enabled on your device. Many
advisories only apply when a specific feature is configured (for example `ip http server`), and
Cisco no longer publishes OVAL definitions, so engineers still read every advisory and check every
device by hand with `show` commands.

psirt-exposure automates that check:

1. **Collect**: pull advisories from the PSIRT openVuln API and devices from config files or NetBox.
2. **Extract**: a security LLM (Cisco Foundation-Sec, run locally) reads the advisory once and turns
   the "vulnerable only if..." condition into a structured, human-reviewable YAML rule.
3. **Match**: a deterministic engine evaluates each rule against each device's version and config.
   No LLM runs per device.
4. **Report**: every device gets one verdict, ranked by active exploitation (CISA KEV):

| Verdict | Meaning |
|---------|---------|
| `AFFECTED` | Vulnerable version and the vulnerable feature is enabled |
| `NOT_AFFECTED_FEATURE_DISABLED` | Vulnerable version, but the feature is not enabled |
| `FIXED_VERSION` | Running a fixed release |
| `MITIGATED` | Vulnerable, but the advisory's workaround is applied |
| `INDETERMINATE` | Needs runtime data; the exact `show` command is listed |

Each verdict comes with the reason, the config lines it was based on (secrets redacted) and a link to the advisory.

Outcomes: one triage table instead of reading N advisories × M devices, evidence that a reviewer
can verify in seconds, KEV-first prioritization, and drift alerts when a config change re-opens an
exposure. On the 60-pair golden set the reviewed rules get every verdict right (an upper bound,
see [Known issues](#known-issues)).

### Architecture

```mermaid
flowchart LR
    subgraph Sources
        PSIRT["Cisco PSIRT openVuln API<br/>(or local CSAF files)"]
        KEV["CISA KEV catalog"]
        INV["Device configs + show version<br/>(files or NetBox)"]
    end
    subgraph Offline["Once per advisory"]
        LLM["Local LLM<br/>Foundation-Sec-8B (Ollama)"]
        DRAFT["Draft rule (YAML)"]
        REVIEW{"Human review"}
    end
    RULES["rules/*.yaml<br/>status: reviewed"]
    PARSE["IOS XE config parser<br/>(ciscoconfparse2)"]
    MATCH["Deterministic matcher<br/>exposure + mitigations + version"]
    OUT["Verdicts with evidence<br/>CLI table / JSON / Markdown / HTML"]
    MCP["MCP server (stdio)<br/>list_devices, list_rules, check, report"]
    WATCH["watch: drift vs. last run"]

    PSIRT -- advisory text --> LLM --> DRAFT --> REVIEW --> RULES
    PSIRT -- affected versions --> MATCH
    KEV -- exploited CVEs --> MATCH
    INV --> PARSE --> MATCH
    RULES --> MATCH
    MATCH --> OUT
    MATCH --> MCP
    MATCH --> WATCH
```

The LLM only turns advisory text into a rule, once, and a human reviews the rule before `check`
uses it. Per-device matching has no LLM in the loop: the same inputs always give the same verdicts.
Configs never leave the host; in live mode only software versions are sent to Cisco.

## Installation

Requirements: Python 3.11+, [git](https://git-scm.com/downloads) and
[uv](https://docs.astral.sh/uv/getting-started/installation/). uv installs a suitable Python if
you do not have one. No account or API key is needed for offline mode.

Install uv:

```bash
# macOS
brew install uv                                     # or the Linux command below
# Linux and macOS
curl -LsSf https://astral.sh/uv/install.sh | sh
# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Clone and install:

```bash
git clone https://github.com/faithere1/psirt-exposure
cd psirt-exposure
uv sync
uv run psirt-exposure --help
```

Tested on macOS; CI runs on Linux (Ubuntu). Windows should work with the same `uv` commands but is
not tested yet.

## Configuration

Offline mode needs no configuration. For live data, copy the template and fill in only what you
use (`.env` is gitignored; never put credentials anywhere else):

```bash
cp .env.example .env        # Windows: copy .env.example .env
```

| Variable | Needed for | Format |
|----------|------------|--------|
| `CISCO_CLIENT_ID`, `CISCO_CLIENT_SECRET` | live advisory/version data (`check` without `--offline`) | Client credentials of a free [Cisco API Console](https://apiconsole.cisco.com) app with the PSIRT openVuln API |
| `NETBOX_URL` | `--netbox` | Base URL with scheme, no `/api` suffix, e.g. `http://127.0.0.1:8000` |
| `NETBOX_TOKEN` | `--netbox` | NetBox API token: v1 (40 hex chars) or v2 (`nbt_<key>.<secret>`) |
| `OPENAI_API_KEY` | `extract --backend openai` only | API key of your OpenAI-compatible server |
| `NETBOX_DB_PASSWORD`, ... | local NetBox lab only | Generated by `uv run python -m psirt_exposure.netbox.secrets >> .env` |

Device data in file mode is one directory per device:

```text
<configs-dir>/<hostname>/running-config.txt   # output of "show running-config" (required)
<configs-dir>/<hostname>/show-version.txt     # output of "show version" (recommended: PID + version)
```

Without `show-version.txt` the version and PID are unknown: a disabled feature still gives
`NOT_AFFECTED_FEATURE_DISABLED`, but an enabled one (or a rule that needs the platform) gives
`INDETERMINATE`. Point `--configs` at your own directory; keep real configs outside this repository.

## Usage

### Check devices (offline)

```bash
uv run psirt-exposure check --offline --evidence                # all sample devices x all rules
uv run psirt-exposure check --offline --device edge-rtr-01 --format json
uv run psirt-exposure check --offline --configs ~/my-configs --rule webui --rule snmp
```

Offline mode reads `rules/` and `samples/configs/<hostname>/{running-config,show-version}.txt`.
Version status comes from the local CSAF files in `tests/fixtures/psirt/` (`--advisories DIR`):
a version listed as `known_affected` for "Cisco IOS XE Software" is affected; an unlisted version
is fixed if its release train is listed or newer than every listed train; an older, unlisted
train (Cisco does not evaluate releases past end of maintenance) is `INDETERMINATE`.
Secrets (SNMP communities, passwords, keys) are redacted in the evidence lines.

### Live mode (openVuln + CISA KEV)

```bash
cp .env.example .env        # then fill in CISCO_CLIENT_ID / CISCO_CLIENT_SECRET
uv run psirt-exposure check --evidence
```

Without `--offline`, `check` asks the PSIRT openVuln API (OAuth2 client credentials from a
[Cisco API Console](https://apiconsole.cisco.com) app) which advisories affect each device's IOS XE
version, one request per distinct version, and flags rule CVEs that are in the
[CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (`KEV` column).
Mix sources with `--versions openvuln|csaf|none` and `--kev cisa|none|FILE`.
Only software versions are sent to Cisco; configs never leave the host.

Live smoke tests are opt-in: `PSIRT_EXPOSURE_LIVE=1 uv run pytest -m live`.

### NetBox inventory

`check --netbox` reads devices from NetBox instead of `--configs`: the device type's part number
(or model) is the PID, and two custom fields on devices hold the data that `show version` and the
config files provide in file mode: `software_version` (text) and `running_config` (long text).
Set `NETBOX_URL` and `NETBOX_TOKEN` in `.env`; v1 (`Token`) and v2 (`nbt_…`, `Bearer`) tokens
both work. Narrow the device query with `--netbox-filter KEY=VALUE` (any NetBox device filter,
repeatable).

A local lab with the sample devices (needs Docker, e.g. `brew install colima docker
docker-compose && colima start`):

```bash
uv run python -m psirt_exposure.netbox.secrets >> .env   # random lab passwords + API token
docker compose --env-file .env -f netbox/docker-compose.yml up -d --wait
uv run psirt-exposure netbox-seed                         # idempotent
uv run psirt-exposure check --offline --netbox --netbox-filter site=psirt-lab
```

NetBox runs on http://127.0.0.1:8000 (user `admin`, password `NETBOX_SUPERUSER_PASSWORD`).
The compose file is a trimmed copy of
[netbox-docker](https://github.com/netbox-community/netbox-docker); `--offline` still allows
`--netbox`, because it only concerns advisory and KEV sources.

### Reports

```bash
uv run psirt-exposure check --offline --format markdown --output report.md
uv run psirt-exposure check --offline --format html --output report.html
```

A report has a verdict summary, a per-device table and one section per `AFFECTED`,
`INDETERMINATE` or `MITIGATED` result: the advisory link and CVEs, CISA KEV dates, the reason, the
redacted evidence lines, the `show` commands that confirm runtime facts, and the fix. Besides
"upgrade to a fixed release", rules can carry IOS XE config snippets: `mitigations[].snippet`
applies the advisory's workaround, `remediation.snippet` removes the exposure (for example
`no vstack` or `no ip http server`). `<name>` marks a value to fill in. The HTML file is
self-contained (no scripts, no external assets).

### MCP server

`psirt-exposure mcp` runs a [Model Context Protocol](https://modelcontextprotocol.io) server over
stdio (official `mcp` Python SDK), so an AI assistant can ask "which of my devices are affected?"
and get deterministic verdicts with evidence.

| Tool | Purpose |
|------|---------|
| `list_devices` | Inventory devices with PID and version (`inventory`: `files` or `netbox`) |
| `list_rules` | Reviewed rules: advisory, CVEs, title, exposure summary |
| `check` | One verdict per device and rule, with reason, evidence, runtime checks, KEV |
| `report` | The Markdown or HTML report described above |

Resource template `psirt-exposure://rules/{rule_id}` returns a rule as YAML. Tools accept device and
rule names, never file paths; the directories are fixed at start-up (`--configs`, `--rules`,
`--advisories`, `--env-file`). Defaults are offline (`versions="csaf"`, `kev="none"`); a client
must ask for `versions="openvuln"`, `kev="cisa"` or `inventory="netbox"` explicitly.

Client configuration (Claude Desktop, Claude Code `.mcp.json`, Cursor, ...):

```json
{
  "mcpServers": {
    "psirt-exposure": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/psirt-exposure", "psirt-exposure", "mcp"]
    }
  }
}
```

Try it with [MCP Inspector](https://github.com/modelcontextprotocol/inspector):

```bash
npx @modelcontextprotocol/inspector uv run --directory "$PWD" psirt-exposure mcp
npx @modelcontextprotocol/inspector --cli uv run --directory "$PWD" psirt-exposure mcp \
  --method tools/call --tool-name check --tool-arg only_findings=true
```

### Drift watch

`watch` re-runs `check` (same source options) and compares the result with the snapshot of the
previous run, so new exposure from a config change, a new device, updated advisory or version
data, or a new KEV listing shows up as a change:

```bash
uv run psirt-exposure watch --offline                     # first run saves the baseline
uv run psirt-exposure watch --offline                     # later runs print the changes
uv run psirt-exposure watch --interval 3600 --count 24    # hourly for a day (live sources)
```

The snapshot lives in `.psirt-exposure/watch-state.json` (`--state`, gitignored) and holds only
verdicts, exposure, mitigation ids, KEV CVEs and redacted evidence text (no line numbers, so an
unrelated edit higher up in a config is not reported). Change kinds: `new`, `gone`, `verdict`,
`evidence`, `kev`. `--format json` prints machine-readable changes. Exit code: 0 no drift,
1 drift in any run (for cron or CI), 2 setup or state-file error.

### Draft rules with an LLM

`psirt-exposure extract` turns advisory text into a `draft` rule. The model reply is constrained by
the rule JSON Schema and then validated like a hand-written rule; invalid replies are retried with
the validation error. Advisory IDs, CVEs and titles are copied from the advisory, never generated.

Default backend: Foundation-Sec-8B-Instruct on a local Ollama (advisories stay on the host).

```bash
ollama pull hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF
ollama create foundation-sec-8b-instruct -f ollama/foundation-sec-8b-instruct.Modelfile
uv run psirt-exposure extract                           # all fixture advisories -> eval/<model>/rules/
uv run psirt-exposure eval-extraction --drafts eval/ollama-foundation-sec-8b-instruct/rules
```

The Modelfile adds the chat template that the published GGUF lacks; without it the system prompt
is dropped. Any OpenAI-compatible server works too (key read from `OPENAI_API_KEY`):

```bash
uv run psirt-exposure extract --backend openai --model <name> --base-url http://localhost:8000/v1
```

Drafts are written under `eval/`, not `rules/`, so `check` ignores them until a human reviews
one, sets `status: reviewed` and moves it into `rules/`.
`eval-extraction` runs drafts and hand rules through the same matcher on the sample devices and
writes `report.md` / `report.json` next to the drafts.

### Evaluation

`uv run psirt-exposure eval-golden` scores final verdicts on 60 held-out advisory×config pairs
(`eval/golden/`); see [eval/README.md](eval/README.md) for the metrics table and caveats.

## Related Sandbox

Try psirt-exposure on a real IOS XE device with a free
[DevNet Sandbox](https://developer.cisco.com/site/sandbox/), for example an always-on or reservable
IOS XE (Catalyst 8000V) or a Cisco Modeling Labs sandbox:

1. Connect to the device over SSH with the credentials shown on the sandbox page.
2. Run `terminal length 0`, then `show running-config` and `show version`.
3. Save the outputs as `~/psirt-lab/<hostname>/running-config.txt` and
   `~/psirt-lab/<hostname>/show-version.txt` (outside this repository).
4. Run `uv run psirt-exposure check --offline --configs ~/psirt-lab --evidence`, or drop
   `--offline` to use live openVuln data.

psirt-exposure only reads the saved text; it never logs in to the device. Sandbox configs contain
real addresses and shared credentials, so do not commit them or paste them into issues.

## Known issues

- Cisco IOS XE only; NX-OS and ASA are not supported yet (the parser and rule interfaces are kept
  platform-agnostic).
- Only advisories with a rule in `rules/` get a config-level verdict (10 today). Other openVuln
  advisories for a device's version are not reported yet.
- Some facts cannot be read from a config (active L2TP tunnels, UDP 500 reachable, IOx running);
  those results are `INDETERMINATE` and list the `show` command to run.
- The golden labels were written by the rule author, so the 60/60 score in
  [eval/README.md](eval/README.md) is an upper bound. Independent labels are very welcome.
- LLM drafts from Foundation-Sec-8B are not good enough to use unreviewed (see the eval report);
  that is why every rule needs `status: reviewed`.
- No client-side throttling for the openVuln API yet; keep long `watch --interval` runs modest.
- psirt-exposure never logs in to devices. Treat its output as triage, not a guarantee; confirm
  with Cisco's advisory and the Cisco Software Checker.

Bugs and wrong verdicts are tracked in [GitHub Issues](https://github.com/faithere1/psirt-exposure/issues);
use the issue templates and attach a minimal **fake** config, never a real one.

## Getting help

- Questions, wrong verdicts and feature requests: open a
  [GitHub issue](https://github.com/faithere1/psirt-exposure/issues).
- Security problems in psirt-exposure: follow [SECURITY.md](SECURITY.md) (private reporting, not
  a public issue).

## Getting involved

The most useful contributions right now:

- **New rules** for feature-dependent IOS XE advisories (one YAML file plus tests).
- **Independent golden labels**: devices and expected verdicts written by someone other than the
  rule author.
- NX-OS and ASA support, openVuln client-side throttling, reporting advisories that have no rule.

[CONTRIBUTING.md](CONTRIBUTING.md) explains the rule workflow and the no-real-data rules. All
participants follow the [Code of Conduct](CODE_OF_CONDUCT.md).

Development checks (the same as CI):

```bash
uv sync
uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest
uv run --with pillow python scripts/demo_gif.py          # regenerate docs/demo.gif
```

## Credits and references

- Advisory data: [Cisco PSIRT openVuln API](https://developer.cisco.com/psirt/) and public CSAF
  documents; exploited-vulnerability data: [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- Config parsing: [ciscoconfparse2](https://github.com/mpenning/ciscoconfparse2).
- Local LLM: [Foundation-Sec-8B-Instruct](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct)
  via [Ollama](https://ollama.com).
- MCP: the official [Model Context Protocol Python SDK](https://github.com/modelcontextprotocol/python-sdk).
- NetBox lab: trimmed from [netbox-docker](https://github.com/netbox-community/netbox-docker).
- Cisco PSIRT: [Security Vulnerability Policy](https://sec.cloudapps.cisco.com/security/center/resources/security_vulnerability_policy.html)
  and the [Cisco Software Checker](https://sec.cloudapps.cisco.com/security/center/softwarechecker.x).

## Licensing info

Copyright 2026 faithere1. Licensed under the Apache License 2.0; see [LICENSE](LICENSE) and
[NOTICE](NOTICE) (third-party attributions).

psirt-exposure is not affiliated with or endorsed by Cisco Systems, Inc.
