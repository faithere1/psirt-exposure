# Cisco DevNet Code Exchange submission

Metadata to paste into the [Code Exchange](https://developer.cisco.com/codeexchange/) submission
form, plus the pre-submission checklist. Code Exchange reads the rest (description, README,
license) from the GitHub repository.

## Metadata

| Field | Value |
|-------|-------|
| Repository | `https://github.com/faithere1/netsec-check-mcp` |
| Title | netsec-check: am I actually affected by this Cisco PSIRT advisory? |
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
Engineers still read each advisory and check each device by hand. netsec-check pulls advisories and
devices (config files or NetBox), turns each advisory's "vulnerable only if..." condition into a
human-reviewed YAML rule (drafted by a local security LLM), and evaluates the rules
deterministically against every device. Each device gets `AFFECTED`, `NOT_AFFECTED_FEATURE_DISABLED`,
`FIXED_VERSION`, `MITIGATED` or `INDETERMINATE`, with the config lines as evidence, CISA KEV
priority and mitigation snippets. An MCP server lets AI assistants ask the same question, and
`watch` reports drift when configs or advisories change.

## Checklist before submitting

- [ ] Repository is public on GitHub, default branch `main`, CI green.
- [ ] README has: what it does, demo GIF, architecture, quick start, usage, limitations,
      getting help, contributing, credits, license.
- [ ] `LICENSE`, `CONTRIBUTING.md`, `SECURITY.md` present.
- [ ] Fresh clone quick start works (`uv sync && uv run netsec-check check --offline`).
- [ ] `gitleaks git --config .gitleaks.toml` over the full history: no leaks.
- [ ] `pip-audit` on the locked dependencies: no known vulnerabilities.
- [ ] No real hostnames, IPs, communities, hashes, serials or tokens in samples, fixtures, eval
      devices or reports.
- [ ] GitHub repository description and topics set (same tags as above).
- [ ] After approval, add the Code Exchange "published" badge to the README.
