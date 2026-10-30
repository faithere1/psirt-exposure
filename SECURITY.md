# Security policy

## Reporting a vulnerability in psirt-exposure

Please report security problems privately through GitHub's
[private vulnerability reporting](https://github.com/faithere1/psirt-exposure/security/advisories/new)
(repository **Security** tab, "Report a vulnerability"). Do not open a public issue.

Include the version or commit, the steps to reproduce, and the impact. Use fake data only; never
send real device configurations or credentials. You should get a first reply within 7 days.

Examples of what counts:

- Secrets (SNMP communities, passwords, keys) that leak unredacted into CLI output, reports, MCP
  responses or the `watch` state file.
- The MCP server reading or writing files outside the directories fixed at start-up.
- Credentials from `.env` sent anywhere other than the Cisco API Console, CISA, or the configured
  NetBox / LLM endpoint.

**A wrong verdict is not normally a security vulnerability** in psirt-exposure; report it as a
regular issue (see [CONTRIBUTING.md](CONTRIBUTING.md)). For vulnerabilities in Cisco products,
contact [Cisco PSIRT](https://sec.cloudapps.cisco.com/security/center/resources/security_vulnerability_policy.html).

## Supported versions

psirt-exposure is pre-1.0; only the latest commit on `main` gets security fixes.

## How psirt-exposure handles your data

- **Configs stay on the host.** Matching runs locally. In live mode only software versions are
  sent to the Cisco PSIRT openVuln API; the CISA KEV feed is a plain download.
- **The LLM is optional and local by default.** `extract` sends advisory text (public data) to the
  configured backend, Ollama on localhost by default. Device configs are never sent to an LLM.
- **Redaction.** SNMP communities, passwords, secrets and keys are replaced by `<redacted>` in
  evidence lines before they reach any output (`src/psirt_exposure/redact.py`).
- **Read-only.** psirt-exposure never logs in to devices and never changes a config; snippets in
  reports are suggestions for a human to review.
- **MCP server.** Tools accept device and rule names, never file paths, and default to offline
  sources; a client must ask for live sources explicitly.

## Project hygiene

- Credentials live only in `.env` (gitignored). The repository is scanned with
  [gitleaks](https://github.com/gitleaks/gitleaks) (`.gitleaks.toml`) over the full history before
  every push and in CI (`security` job), and dependencies with [pip-audit](https://github.com/pypa/pip-audit):
  `uv export --format requirements-txt --no-emit-project > /tmp/req.txt && uvx pip-audit -r /tmp/req.txt --disable-pip`.
- All sample configs, fixtures and eval devices use documentation IP ranges and fake names,
  hashes, communities and serials. Advisory fixtures are unmodified public Cisco CSAF documents.
