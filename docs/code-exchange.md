# Cisco DevNet Code Exchange submission

Metadata to paste into the [Code Exchange](https://developer.cisco.com/codeexchange/) submission
form, plus the pre-submission checklist. Code Exchange reads the rest (description, README,
license) from the GitHub repository.

## Metadata

| Field | Value |
|-------|-------|
| Repository | `https://github.com/faithere1/psirt-exposure` |
| Title | psirt-exposure: am I actually affected by this Cisco PSIRT advisory? |
| Short description | Match Cisco PSIRT advisories against IOS XE configs and get a per-device verdict with config evidence; CLI and MCP server. |
| Language | Python |
| License | Apache-2.0 |
| Cisco products / technologies | Cisco IOS XE, Cisco PSIRT openVuln API, Cisco Foundation AI (Foundation-Sec-8B) |
| Other technologies | Model Context Protocol (MCP), NetBox, CISA KEV, CSAF 2.0, Ollama |
| Categories | Security, Network automation, Vulnerability management, AI / LLM |
| Tags | `psirt`, `openvuln`, `ios-xe`, `vulnerability-management`, `mcp`, `netbox`, `llm`, `security` |

### Use case (for the form)

Cisco's PSIRT openVuln API says which software versions an advisory affects, but many advisories
only apply when a specific feature is configured (for example the web UI, Smart Install or SNMP).
Engineers still read each advisory and check each device by hand. psirt-exposure pulls advisories and
devices (config files or NetBox), turns each advisory's "vulnerable only if..." condition into a
human-reviewed YAML rule (drafted by a local security LLM), and evaluates the rules
deterministically against every device. Each device gets `AFFECTED`, `NOT_AFFECTED_FEATURE_DISABLED`,
`FIXED_VERSION`, `MITIGATED` or `INDETERMINATE`, with the config lines as evidence, CISA KEV
priority and mitigation snippets. An MCP server lets AI assistants ask the same question, and
`watch` reports drift when configs or advisories change.

## Official requirements

From the [Code Exchange About page](https://developer.cisco.com/site/codeexchange-about-page/)
(checked 2026-10-30) and Cisco's
[repo template](https://github.com/CiscoDevNet/code-exchange-repo-template/tree/main/manual-sample-repo):

| Requirement | Where it is met |
|-------------|-----------------|
| Relevant to Cisco technologies | IOS XE, PSIRT openVuln API, Foundation-Sec |
| Publicly available on GitHub | to do: create the public repo and push |
| OSI-approved license | Apache-2.0 in `LICENSE`, copyright and attributions in `NOTICE` |
| Clear technical documentation | `README.md` in the template's section order: descriptive title, description, screenshot (demo GIF), Use Case, Installation (macOS/Linux/Windows), Configuration (env var formats), Usage, Related Sandbox, Known issues, Getting help, Getting involved, Credits and references, Licensing info |
| Template extras | `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1), `NOTICE`, issue templates |
| Template best practices | credentials only in `.env` (no files to rename or edit), `--help` on every command and usage on missing arguments, sandbox instructions, install links |

Code Exchange scores every repo 1-10 from an automated check of these requirements plus GitHub
activity (stars, forks, watchers) and recalculates the score over time; the score is one input to
the publishing decision. Search uses GitHub topics and the README's first- and second-level
headings, and the tile shows the GitHub repository description (or the first README lines).

GitHub repository settings to fill in:

- **Description:** Am I actually affected? Match Cisco PSIRT advisories against IOS XE configs, with evidence. CLI + MCP server.
- **Topics:** `cisco`, `psirt`, `openvuln`, `ios-xe`, `vulnerability-management`, `network-automation`, `mcp`, `netbox`, `llm`, `security`
- **Security:** enable private vulnerability reporting (SECURITY.md and CODE_OF_CONDUCT.md point to it).

## Checklist before submitting

- [ ] Public GitHub repo `faithere1/psirt-exposure`, default branch `main`, both CI jobs green
      (`test`, `security`).
- [ ] Description, topics and private vulnerability reporting set (see above).
- [ ] `gitleaks git --config .gitleaks.toml` over the full history right before the push: no leaks.
- [ ] `pip-audit` on the locked dependencies: no known vulnerabilities.
- [ ] Fresh clone quick start works (`uv sync && uv run psirt-exposure check --offline`).
- [ ] The demo GIF renders on the GitHub README page.
- [ ] Submit at <https://developer.cisco.com/codeexchange/github/submit> (free DevNet account).
- [ ] After approval, add the Code Exchange "published" badge to the README.
