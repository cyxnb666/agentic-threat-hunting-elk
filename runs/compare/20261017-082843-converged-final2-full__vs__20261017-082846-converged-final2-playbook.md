# Run comparison: 20261017-082843-converged-final2-full vs 20261017-082846-converged-final2-playbook

Hypothesis: An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

| | 20261017-082843-converged-final2-full | 20261017-082846-converged-final2-playbook |
|---|---|---|
| Verdict | Confirmed | Confirmed |
| Ground truth sub-steps found (6.A/6.B/6.C) | 3/3 (6.A:yes, 6.B:yes, 6.C:yes) | 2/3 (6.A:no, 6.B:yes, 6.C:yes) |
| Techniques with malicious/suspicious findings | T1003, T1003.001, T1056, T1056.001, T1111, T1552.001, T1552.004, T1555 | T1003.001, T1003.005, T1056.001, T1056.004, T1552, T1552.001, T1552.004, T1555.004, T1558.003 |
| Hosts implicated | nashua.dmevals.local, scranton.dmevals.local | nashua.dmevals.local, newyork.dmevals.local, scranton.dmevals.local |
| Findings (malicious+suspicious / all) | 20 / 66 | 21 / 62 |
| Incidents after consolidation | 9 | 10 |
| Verified evidence events | 44 | 26 |
| Rejected evidence items | 0 | 2 |
| Planned checks / all queries | 355 / 1168 | 363 / 1155 |
| LLM calls / tokens | 127 / {'prompt': 3773654, 'completion': 118711} | 126 / {'prompt': 3257650, 'completion': 80156} |
| Duration (s) | 652.7 | 484.0 |

| Similarity | Value |
|---|---|
| verdict_equal | True |
| techniques_jaccard | 0.308 |
| technique_families_jaccard | 0.667 |
| evidence_jaccard | 0.273 |
| planned_query_jaccard | 0.087 |
| coverage_cells_differing | 5 of 265 |
| ground_truth_equal | False |

Jaccard = |A∩B| / |A∪B| (1.0 = identical sets). Planned queries are compared after lower-casing and dropping size/fields/sort.

Only in 20261017-082843-converged-final2-full (techniques): ['T1003', 'T1056', 'T1111', 'T1555']
Only in 20261017-082846-converged-final2-playbook (techniques): ['T1003.005', 'T1056.004', 'T1552', 'T1555.004', 'T1558.003']
