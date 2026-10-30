# Evaluation

`<backend-model>/rules/` holds draft rules from `psirt-exposure extract` plus `extraction.json`
(attempts, validation errors and raw model replies). `<backend-model>/report.{md,json}` is the
output of `psirt-exposure eval-extraction`. Regenerate the report after changing drafts or labels:

```bash
uv run psirt-exposure eval-extraction --drafts eval/ollama-foundation-sec-8b-instruct/rules
```

## Phase 4 result: Foundation-Sec-1.1-8B-Instruct (Q4_K_M, Ollama, 2026-10-30)

Report: [ollama-foundation-sec-8b-instruct/report.md](ollama-foundation-sec-8b-instruct/report.md).

| Metric | Value |
|---|---|
| Schema-valid drafts | 8/10 |
| Drafts correct on every device | 0/10 |
| Device×advisory accuracy | 48/80 (60%), below the "always absent" baseline (57/80) |
| Accuracy on non-`absent` labels | 0/23 |

Every valid draft is too strict: it never fires on an exposed device. Typical errors:

- **Show commands and runtime output used as config lines**: `^show cip status$`, and for IOx
  `^iox service (CAF) : Running$` added to `all_of`, which makes the exposure impossible.
- **Product names as platform regexes**: `affected_platforms: ["Cisco IOS XE", ...]` or
  `"800 Series Industrial ISRs"` instead of PID patterns, so devices fall out as
  `not_applicable_platform` or the condition never matches.
- **Wrong config scope**: `ip nat inside` / `outside` written as global lines (they are interface
  sub-commands).
- **Turning a feature off written as a mitigation** (`no iox`, `no ip http server`), although the
  prompt says otherwise. Harmless for scoring, but noisy for reviewers.
- **Schema failures** (smart-install, snmp): an empty `affected_platforms` list on every retry.

Takeaways:

1. The pipeline works end to end with schema-constrained decoding on a local 8B model, and the
   drafts are a useful starting point for a reviewer (the right commands usually appear somewhere),
   but **drafts must not be used for verdicts without review**. This confirms the `draft` /
   `reviewed` split and the "deterministic matcher, LLM only extracts" design.
2. Setup pitfalls found while running it (both handled in code or the repo):
   - the published GGUF has no chat template, so Ollama dropped the system prompt
     (fixed by `ollama/foundation-sec-8b-instruct.Modelfile`);
   - Ollama 0.15 segfaults in schema-to-grammar on the JSON Schema `pattern` keyword, and grammar
     decoders do not handle recursive schemas (fixed by `bounded_schema`).
3. Ideas to try later (not done here): a larger or hosted model via the OpenAI-compatible backend
   for comparison, few-shot examples drawn from reviewed rules with leave-one-out, and a
   lint step that rejects `show ...` patterns and non-regex platform names before scoring.

## Phase 8: golden eval set (final verdicts, held-out devices)

`golden/cases.yaml` holds 60 advisory×config pairs on 6 devices in `golden/devices/` that were
written for this set and never used while developing `rules/` (the rules were tuned on
`samples/configs/`). Each pair has the expected exposure label and the expected final verdict
with offline CSAF version data; every verdict class appears at least 3 times. Tricky cases
include NVI NAT with only the UDP DNS ALG off, a crypto map with an IKEv2 profile that is not
applied, an SNMPv3 group without a read view, an SNMPv3 group without users, one HTTP server
with session modules none and the other without, snooping ranges that include VLAN 1, partial
snooping on unlisted platforms, and a device without `show version`.

```bash
uv run psirt-exposure eval-golden                      # reviewed rules -> golden/report.md
uv run psirt-exposure eval-golden --rules eval/ollama-foundation-sec-8b-instruct/rules \
  --out eval/ollama-foundation-sec-8b-instruct/golden  # LLM drafts
uv run psirt-exposure eval-golden --min-accuracy 1.0   # CI gate: exit 1 below the threshold
```

A test fails if `golden/report.md` is stale, so regenerate it after changing rules or cases.

| Rule set | Verdict accuracy | Exposure accuracy | AFFECTED precision | AFFECTED recall |
|---|---|---|---|---|
| Reviewed rules (`rules/`) | 60/60 (1.00) | 60/60 (1.00) | 1.00 | 1.00 |
| Foundation-Sec-8B drafts (Phase 4) | 32/60 (0.53) | 29/60 (0.48) | - (never predicted) | 0.00 |
| Baseline: always `NOT_AFFECTED_FEATURE_DISABLED` | 38/60 (0.63) | - | - | 0.00 |

Reports: [golden/report.md](golden/report.md),
[ollama-foundation-sec-8b-instruct/golden/report.md](ollama-foundation-sec-8b-instruct/golden/report.md).

Caveats: the golden labels were written by the same agent that wrote the rules (from the
advisory text, before scoring), so 60/60 is an upper bound, not independent validation; an
independent reviewer should label new devices before the set is trusted for regressions. The
version part of each verdict follows the CSAF `known_affected` lists, so it checks the version
logic against Cisco's data rather than against a human. The drafts again score below the
"always not affected" baseline and never flag an affected device, which matches Phase 4.
