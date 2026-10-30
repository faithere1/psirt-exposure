# Agent rules for this repository

## Phase workflow (mandatory, saves tokens)
1. At session start, read `PROGRESS.md` first. Work **only** on the first phase whose status is not ☑.
   Do not explore the whole repo; read only the files that phase needs.
2. One phase per session. Never start the next phase in the same session.
3. At the end of the phase:
   - run the phase's exit check (see the phase table in `PROGRESS.md`),
   - **append** a log entry to `PROGRESS.md` (never edit or delete earlier entries),
   - update the phase's status in the table,
   - tell the user the phase is done and to start a new session for the next one.
4. If the phase cannot be finished in one session, mark it ◐ and write an exact resume point.
5. Decisions that affect later phases go under "Global decisions" in `PROGRESS.md`.

## Project rules
- Everything in the repo is **English**: code, comments, docs, commit messages, CLI output.
  (Chat with the user may be in Turkish.)
- Secrets live only in `.env` (gitignored). Never print, log, commit or ask the user to paste them.
- Never push to a remote before running a secret scan (`gitleaks detect` over the full history).
- Fixtures, sample configs and recorded API responses must contain no real data: use documentation
  IP ranges and fake hostnames, passwords, SNMP communities and serial numbers. Never record OAuth
  tokens or `Authorization` headers in fixtures.
- Python 3.11+, managed with `uv`. Code lives in `src/netsec_check/`, tests in `tests/`.
- Before finishing any phase: `uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest`.
- Matching must stay deterministic; the LLM only extracts rules from advisory text.
- Tests must run offline (use fixtures in `tests/fixtures/`); live API tests are opt-in.
