# Run comparison: 20261022-135212-converged-recheck-a vs 20261022-135215-converged-recheck-b

Hypothesis: An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

| | 20261022-135212-converged-recheck-a | 20261022-135215-converged-recheck-b |
|---|---|---|
| Verdict | Confirmed | Confirmed |
| Ground truth sub-steps found (6.A/6.B/6.C) | 3/3 (6.A:yes, 6.B:yes, 6.C:yes) | 3/3 (6.A:yes, 6.B:yes, 6.C:yes) |
| Techniques with malicious/suspicious findings | T1003.001, T1003.002, T1056.002, T1187, T1552, T1552.001, T1649 | T1003.001, T1003.002, T1056.002, T1552, T1552.001, T1552.004, T1555.003, T1556, T1556.008 |
| Hosts implicated | nashua.dmevals.local, newyork.dmevals.local, scranton.dmevals.local | nashua.dmevals.local, scranton.dmevals.local |
| Findings (malicious+suspicious / all) | 19 / 57 | 29 / 66 |
| Incidents after consolidation | 9 | 18 |
| Verified evidence events | 43 | 56 |
| Rejected evidence items | 3 | 0 |
| Planned checks / all queries | 319 / 1214 | 322 / 1203 |
| LLM calls / tokens | 150 / {'prompt': 4722126, 'completion': 134347} | 149 / {'prompt': 4558276, 'completion': 141262} |
| Duration (s) | 649.4 | 655.7 |

| Similarity | Value |
|---|---|
| verdict_equal | True |
| techniques_jaccard | 0.455 |
| technique_families_jaccard | 0.429 |
| evidence_jaccard | 0.303 |
| planned_query_jaccard | 0.12 |
| coverage_cells_differing | 16 of 265 |
| ground_truth_equal | True |

Jaccard = |A∩B| / |A∪B| (1.0 = identical sets). Planned queries are compared after lower-casing and dropping size/fields/sort.

Only in 20261022-135212-converged-recheck-a (techniques): ['T1187', 'T1649']
Only in 20261022-135215-converged-recheck-b (techniques): ['T1552.004', 'T1555.003', 'T1556', 'T1556.008']
