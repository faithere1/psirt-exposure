# Golden eval report

- cases: `eval/golden/cases.yaml`
- rules: `rules`
- versions: `csaf (offline)`

## Summary

| Metric | Value |
|---|---|
| Cases (advisory x config pairs) | 60 (6 devices, 10 rules) |
| Verdict accuracy | 60/60 (1.00) |
| Exposure accuracy | 60/60 (1.00) |
| AFFECTED precision | 1.00 |
| AFFECTED recall | 1.00 |

## Per verdict

| Verdict | Support | Predicted | Precision | Recall | F1 |
|---|---|---|---|---|---|
| AFFECTED | 10 | 10 | 1.00 | 1.00 | 1.00 |
| NOT_AFFECTED_FEATURE_DISABLED | 38 | 38 | 1.00 | 1.00 | 1.00 |
| FIXED_VERSION | 5 | 5 | 1.00 | 1.00 | 1.00 |
| MITIGATED | 4 | 4 | 1.00 | 1.00 | 1.00 |
| INDETERMINATE | 3 | 3 | 1.00 | 1.00 | 1.00 |

## Per rule

| Rule | Correct |
|---|---|
| cip | 6/6 |
| dhcp-snooping | 6/6 |
| ikev1 | 6/6 |
| ikev2 | 6/6 |
| iox | 6/6 |
| l2tp | 6/6 |
| nat-dns-alg | 6/6 |
| smart-install | 6/6 |
| snmp | 6/6 |
| webui | 6/6 |

## Confusion (expected -> predicted)

| Expected | Predicted | Count |
|---|---|---|
| AFFECTED | AFFECTED | 10 |
| FIXED_VERSION | FIXED_VERSION | 5 |
| INDETERMINATE | INDETERMINATE | 3 |
| MITIGATED | MITIGATED | 4 |
| NOT_AFFECTED_FEATURE_DISABLED | NOT_AFFECTED_FEATURE_DISABLED | 38 |

## Mismatches

None.
