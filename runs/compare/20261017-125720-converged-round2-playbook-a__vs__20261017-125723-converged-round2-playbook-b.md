# Run comparison: 20261017-125720-converged-round2-playbook-a vs 20261017-125723-converged-round2-playbook-b

Hypothesis: An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

| | 20261017-125720-converged-round2-playbook-a | 20261017-125723-converged-round2-playbook-b |
|---|---|---|
| Verdict | Confirmed | Confirmed |
| Ground truth sub-steps found (6.A/6.B/6.C) | 3/3 (6.A:yes, 6.B:yes, 6.C:yes) | 3/3 (6.A:yes, 6.B:yes, 6.C:yes) |
| Techniques with malicious/suspicious findings | T1003.001, T1056.001, T1187, T1552, T1552.001, T1552.004 | T1003.001, T1056.001, T1187, T1539, T1552, T1552.001, T1552.004, T1649 |
| Hosts implicated | nashua.dmevals.local, scranton.dmevals.local, simplerockbuild.simplerock.lan | nashua.dmevals.local, scranton.dmevals.local, simplerockbuild.simplerock.lan |
| Findings (malicious+suspicious / all) | 29 / 65 | 29 / 67 |
| Incidents after consolidation | 19 | 11 |
| Verified evidence events | 68 | 55 |
| Rejected evidence items | 0 | 1 |
| Planned checks / all queries | 363 / 1352 | 363 / 1340 |
| LLM calls / tokens | 158 / {'prompt': 5131837, 'completion': 104249} | 165 / {'prompt': 5160678, 'completion': 105958} |
| Duration (s) | 505.9 | 524.9 |

| Similarity | Value |
|---|---|
| verdict_equal | True |
| techniques_jaccard | 0.75 |
| technique_families_jaccard | 0.667 |
| evidence_jaccard | 0.367 |
| planned_query_jaccard | 0.993 |
| coverage_cells_differing | 0 of 265 |
| ground_truth_equal | True |

Jaccard = |A∩B| / |A∪B| (1.0 = identical sets). Planned queries are compared after lower-casing and dropping size/fields/sort.

Only in 20261017-125720-converged-round2-playbook-a (techniques): []
Only in 20261017-125723-converged-round2-playbook-b (techniques): ['T1539', 'T1649']
