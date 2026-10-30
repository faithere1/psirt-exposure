# LLM rule extraction: accuracy report

- drafts: `eval/ollama-foundation-sec-8b-instruct/rules`
- backend: `ollama:foundation-sec-8b-instruct`
- devices: `8`

Each draft rule is run through the deterministic matcher on every sample device and the
config-level result is compared with `samples/configs/labels.yaml`. The hand-written
rules in `rules/` are scored the same way as a reference.

## Summary

| Metric | Value |
|---|---|
| Schema-valid draft rules | 8/10 (80%) |
| Rules correct on every device | 0/10 (0%) |
| Draft device×advisory accuracy | 48/80 (60%) |
| Draft accuracy on non-`absent` labels | 0/23 (0%) |
| Draft agrees with hand rule | 48/80 (60%) |
| Hand rule accuracy (reference) | 80/80 (100%) |
| Baseline: always `absent` | 57/80 (71%) |

## Per advisory

| Advisory | Valid | Attempts | Correct | Non-absent correct | Agrees with hand |
|---|---|---|---|---|---|
| cip | yes | 1 | 7/8 (88%) | 0/1 (0%) | 7/8 (88%) |
| dhcp-snooping | yes | 1 | 6/8 (75%) | 0/2 (0%) | 6/8 (75%) |
| ikev1 | yes | 2 | 6/8 (75%) | 0/2 (0%) | 6/8 (75%) |
| ikev2 | yes | 1 | 6/8 (75%) | 0/2 (0%) | 6/8 (75%) |
| iox | yes | 1 | 7/8 (88%) | 0/1 (0%) | 7/8 (88%) |
| l2tp | yes | 1 | 6/8 (75%) | 0/2 (0%) | 6/8 (75%) |
| nat-dns-alg | yes | 1 | 5/8 (62%) | 0/3 (0%) | 5/8 (62%) |
| smart-install | no | 3 | 0/8 (0%) | 0/1 (0%) | 0/8 (0%) |
| snmp | no | 3 | 0/8 (0%) | 0/6 (0%) | 0/8 (0%) |
| webui | yes | 1 | 5/8 (62%) | 0/3 (0%) | 5/8 (62%) |

## Mismatches

| Advisory | Device | Label | Draft | Hand |
|---|---|---|---|---|
| cip | ind-sw-01 | present | absent | present |
| dhcp-snooping | access-sw-01 | not_applicable_platform | absent | not_applicable_platform |
| dhcp-snooping | branch-isr-01 | present | absent | present |
| ikev1 | edge-rtr-02 | present | absent | present |
| ikev1 | vpn-hub-01 | present | absent | present |
| ikev2 | edge-rtr-01 | present | absent | present |
| ikev2 | vpn-hub-01 | present | absent | present |
| iox | branch-isr-01 | present | absent | present |
| l2tp | edge-rtr-02 | present | absent | present |
| l2tp | vpn-hub-01 | present | absent | present |
| nat-dns-alg | branch-isr-01 | present | absent | present |
| nat-dns-alg | edge-rtr-01 | present | absent | present |
| nat-dns-alg | edge-rtr-02 | mitigated | absent | mitigated |
| smart-install | access-sw-01 | present | no-rule | present |
| smart-install | access-sw-02 | absent | no-rule | absent |
| smart-install | branch-isr-01 | absent | no-rule | absent |
| smart-install | dc-vrtr-01 | absent | no-rule | absent |
| smart-install | edge-rtr-01 | absent | no-rule | absent |
| smart-install | edge-rtr-02 | absent | no-rule | absent |
| smart-install | ind-sw-01 | absent | no-rule | absent |
| smart-install | vpn-hub-01 | absent | no-rule | absent |
| snmp | access-sw-01 | present | no-rule | present |
| snmp | access-sw-02 | mitigated | no-rule | mitigated |
| snmp | branch-isr-01 | absent | no-rule | absent |
| snmp | dc-vrtr-01 | absent | no-rule | absent |
| snmp | edge-rtr-01 | present | no-rule | present |
| snmp | edge-rtr-02 | mitigated | no-rule | mitigated |
| snmp | ind-sw-01 | mitigated | no-rule | mitigated |
| snmp | vpn-hub-01 | present | no-rule | present |
| webui | access-sw-01 | present | absent | present |
| webui | branch-isr-01 | present | absent | present |
| webui | edge-rtr-01 | present | not_applicable_platform | present |
