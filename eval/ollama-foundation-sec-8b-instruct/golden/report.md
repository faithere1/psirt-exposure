# Golden eval report

- cases: `eval/golden/cases.yaml`
- rules: `eval/ollama-foundation-sec-8b-instruct/rules`
- versions: `csaf (offline)`

## Summary

| Metric | Value |
|---|---|
| Cases (advisory x config pairs) | 60 (6 devices, 10 rules) |
| Verdict accuracy | 32/60 (0.53) |
| Exposure accuracy | 29/60 (0.48) |
| AFFECTED precision | - |
| AFFECTED recall | 0.00 |

## Per verdict

| Verdict | Support | Predicted | Precision | Recall | F1 |
|---|---|---|---|---|---|
| AFFECTED | 10 | 0 | - | 0.00 | - |
| NOT_AFFECTED_FEATURE_DISABLED | 38 | 47 | 0.66 | 0.82 | 0.73 |
| FIXED_VERSION | 5 | 0 | - | 0.00 | - |
| MITIGATED | 4 | 0 | - | 0.00 | - |
| INDETERMINATE | 3 | 1 | 1.00 | 0.33 | 0.50 |

## Per rule

| Rule | Correct |
|---|---|
| cip | 5/6 |
| dhcp-snooping | 6/6 |
| ikev1 | 5/6 |
| ikev2 | 4/6 |
| iox | 4/6 |
| l2tp | 3/6 |
| nat-dns-alg | 3/6 |
| smart-install | 0/6 |
| snmp | 0/6 |
| webui | 2/6 |

## Confusion (expected -> predicted)

| Expected | Predicted | Count |
|---|---|---|
| AFFECTED | NOT_AFFECTED_FEATURE_DISABLED | 8 |
| AFFECTED | no-rule | 2 |
| FIXED_VERSION | NOT_AFFECTED_FEATURE_DISABLED | 4 |
| FIXED_VERSION | no-rule | 1 |
| INDETERMINATE | INDETERMINATE | 1 |
| INDETERMINATE | NOT_AFFECTED_FEATURE_DISABLED | 1 |
| INDETERMINATE | no-rule | 1 |
| MITIGATED | NOT_AFFECTED_FEATURE_DISABLED | 3 |
| MITIGATED | no-rule | 1 |
| NOT_AFFECTED_FEATURE_DISABLED | NOT_AFFECTED_FEATURE_DISABLED | 31 |
| NOT_AFFECTED_FEATURE_DISABLED | no-rule | 7 |

## Mismatches

| Case | Expected | Predicted | Note |
|---|---|---|---|
| gold-edge-01/webui | MITIGATED (mitigated) | NOT_AFFECTED_FEATURE_DISABLED (absent) | Only ip http server is on and its active session modules are none. |
| gold-edge-01/smart-install | NOT_AFFECTED_FEATURE_DISABLED (absent) | no-rule (no-rule) | Router; no Smart Install client. |
| gold-edge-01/snmp | AFFECTED (present) | no-rule (no-rule) | SNMPv3 group and user; the group has no read view, so it sees every OID. |
| gold-edge-01/ikev2 | AFFECTED (present) | NOT_AFFECTED_FEATURE_DISABLED (absent) | Tunnel10 uses tunnel protection with IPSEC-HUB, which sets ikev2-profile. |
| gold-edge-01/l2tp | FIXED_VERSION (present) | NOT_AFFECTED_FEATURE_DISABLED (absent) | xconnect via pseudowire-class PW-L2TP (encapsulation l2tpv3); 17.6.4 is not listed. |
| gold-edge-01/nat-dns-alg | FIXED_VERSION (present) | NOT_AFFECTED_FEATURE_DISABLED (absent) | NVI NAT (ip nat enable); only the UDP DNS ALG is off, so not mitigated. |
| gold-isr-02/webui | AFFECTED (present) | NOT_AFFECTED_FEATURE_DISABLED (not_applicable_platform) | HTTPS session modules are none, but plain ip http server is on with default modules. |
| gold-isr-02/smart-install | NOT_AFFECTED_FEATURE_DISABLED (absent) | no-rule (no-rule) |  |
| gold-isr-02/snmp | AFFECTED (present) | no-rule (no-rule) | One community uses the excluding view, the RW community has no view. |
| gold-isr-02/ikev1 | AFFECTED (present) | NOT_AFFECTED_FEATURE_DISABLED (absent) | CMAP-LEGACY (no ikev2-profile) is applied to Gi0/0/0; ISR 4000 is listed. |
| gold-isr-02/l2tp | AFFECTED (present) | NOT_AFFECTED_FEATURE_DISABLED (absent) | vpdn enable plus a vpdn-group with protocol l2tp (LNS). |
| gold-isr-02/dhcp-snooping | NOT_AFFECTED_FEATURE_DISABLED (not_applicable_platform) | NOT_AFFECTED_FEATURE_DISABLED (absent) | Partial coverage (VLAN 10 of 1, 10, 30), but ISR 4000 is not an affected platform. |
| gold-sw-01/smart-install | FIXED_VERSION (present) | no-rule (no-rule) | Catalyst 3650 without no vstack; 16.12 is newer than every train in the 2018 advisory. |
| gold-sw-01/snmp | MITIGATED (mitigated) | no-rule (no-rule) | The only community reads through a view that excludes cafSessionMethodsInfoEntry. |
| gold-sw-01/dhcp-snooping | NOT_AFFECTED_FEATURE_DISABLED (not_applicable_platform) | NOT_AFFECTED_FEATURE_DISABLED (absent) | VLAN 99 is not snooped (partial), but Catalyst 3650 is not an affected platform. |
| gold-ie-01/webui | AFFECTED (present) | NOT_AFFECTED_FEATURE_DISABLED (absent) | ip http secure-server alone enables the web UI. |
| gold-ie-01/smart-install | NOT_AFFECTED_FEATURE_DISABLED (absent) | no-rule (no-rule) |  |
| gold-ie-01/snmp | NOT_AFFECTED_FEATURE_DISABLED (absent) | no-rule (no-rule) |  |
| gold-ie-01/cip | FIXED_VERSION (present) | NOT_AFFECTED_FEATURE_DISABLED (absent) | cip enable on Vlan50; 17.9.1 is not in the advisory's affected list. |
| gold-ie-01/iox | AFFECTED (present) | NOT_AFFECTED_FEATURE_DISABLED (absent) | iox plus ip http secure-server. |
| gold-vrtr-02/webui | MITIGATED (mitigated) | NOT_AFFECTED_FEATURE_DISABLED (absent) | Both HTTP servers on, both with session modules none. |
| gold-vrtr-02/smart-install | NOT_AFFECTED_FEATURE_DISABLED (absent) | no-rule (no-rule) |  |
| gold-vrtr-02/snmp | NOT_AFFECTED_FEATURE_DISABLED (absent) | no-rule (no-rule) | An SNMPv3 group without any SNMPv3 user and no community: SNMP is not usable. |
| gold-vrtr-02/ikev2 | AFFECTED (present) | NOT_AFFECTED_FEATURE_DISABLED (absent) | CMAP-CLOUD sets ikev2-profile and is applied to GigabitEthernet1. |
| gold-vrtr-02/iox | AFFECTED (present) | NOT_AFFECTED_FEATURE_DISABLED (absent) | iox plus HTTP servers; web UI session modules do not mitigate the IOx advisory. |
| gold-vrtr-02/l2tp | FIXED_VERSION (present) | NOT_AFFECTED_FEATURE_DISABLED (absent) | Direct xconnect with encapsulation l2tpv3; 17.12.1a is not listed. |
| gold-vrtr-02/nat-dns-alg | MITIGATED (mitigated) | NOT_AFFECTED_FEATURE_DISABLED (absent) | NAT inside/outside, DNS ALG off for both TCP and UDP. |
| gold-cfgonly-03/webui | INDETERMINATE (present) | INDETERMINATE (None) | Feature on, version unknown. |
| gold-cfgonly-03/smart-install | INDETERMINATE (None) | no-rule (no-rule) | Exposure depends on the platform, which is unknown without show version. |
| gold-cfgonly-03/snmp | NOT_AFFECTED_FEATURE_DISABLED (absent) | no-rule (no-rule) |  |
| gold-cfgonly-03/nat-dns-alg | INDETERMINATE (present) | NOT_AFFECTED_FEATURE_DISABLED (absent) | NAT inside/outside, version unknown. |
