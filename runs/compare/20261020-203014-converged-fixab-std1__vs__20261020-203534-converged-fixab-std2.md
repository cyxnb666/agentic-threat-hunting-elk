# Run comparison: 20261020-203014-converged-fixab-std1 vs 20261020-203534-converged-fixab-std2

Hypothesis: An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

| | 20261020-203014-converged-fixab-std1 | 20261020-203534-converged-fixab-std2 |
|---|---|---|
| Verdict | Confirmed | Confirmed |
| Ground truth sub-steps found (6.A/6.B/6.C) | 3/3 (6.A:yes, 6.B:yes, 6.C:yes) | 3/3 (6.A:yes, 6.B:yes, 6.C:yes) |
| Techniques with malicious/suspicious findings | T1003, T1003.001, T1003.002, T1056, T1552.001, T1552.002, T1552.004, T1555.003, T1555.004, T1557, T1557.001, T1557.002, T1606.001 | T1003.001, T1056.001, T1056.002, T1110.002, T1187, T1552.001, T1552.004, T1558.003, T1649 |
| Hosts implicated | bobs.bigwheel.local, nashua.dmevals.local, scranton.dmevals.local, simplerockbuild.simplerock.lan | nashua.dmevals.local, newyork.dmevals.local, scranton.dmevals.local, simplerockbuild.simplerock.lan |
| Findings (malicious+suspicious / all) | 29 / 63 | 30 / 68 |
| Incidents after consolidation | 18 | 12 |
| Verified evidence events | 54 | 61 |
| Rejected evidence items | 2 | 2 |
| Planned checks / all queries | 315 / 1212 | 318 / 1270 |
| LLM calls / tokens | 182 / {'prompt': 4296252, 'completion': 147268} | 156 / {'prompt': 4793219, 'completion': 146709} |
| Duration (s) | 671.5 | 675.2 |

| Similarity | Value |
|---|---|
| verdict_equal | True |
| techniques_jaccard | 0.158 |
| technique_families_jaccard | 0.3 |
| evidence_jaccard | 0.337 |
| planned_query_jaccard | 0.095 |
| coverage_cells_differing | 37 of 265 |
| ground_truth_equal | True |

Jaccard = |A∩B| / |A∪B| (1.0 = identical sets). Planned queries are compared after lower-casing and dropping size/fields/sort.

Only in 20261020-203014-converged-fixab-std1 (techniques): ['T1003', 'T1003.002', 'T1056', 'T1552.002', 'T1555.003', 'T1555.004', 'T1557', 'T1557.001', 'T1557.002', 'T1606.001']
Only in 20261020-203534-converged-fixab-std2 (techniques): ['T1056.001', 'T1056.002', 'T1110.002', 'T1187', 'T1558.003', 'T1649']
