# Run comparison: 20261017-075714-converged-exp-B3-playbook vs 20261017-075717-converged-exp-B4-playbook

Hypothesis: An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

| | 20261017-075714-converged-exp-B3-playbook | 20261017-075717-converged-exp-B4-playbook |
|---|---|---|
| Verdict | Confirmed | Confirmed |
| Ground truth sub-steps found (6.A/6.B/6.C) | 3/3 (6.A:yes, 6.B:yes, 6.C:yes) | 3/3 (6.A:yes, 6.B:yes, 6.C:yes) |
| Techniques with malicious/suspicious findings | T1003.001, T1003.002, T1187, T1552.001, T1555.003, T1558.001, T1649 | T1003, T1003.001, T1056.001, T1056.004, T1187, T1212, T1552, T1552.001, T1552.004, T1555.004, T1649 |
| Hosts implicated | nashua.dmevals.local, newyork.dmevals.local, scranton.dmevals.local, simplerockbuild.simplerock.lan | nashua.dmevals.local, scranton.dmevals.local, simplerockbuild.simplerock.lan |
| Findings (malicious+suspicious / all) | 19 / 59 | 24 / 68 |
| Incidents after consolidation | 11 | 21 |
| Verified evidence events | 47 | 37 |
| Rejected evidence items | 0 | 0 |
| Planned checks / all queries | 363 / 1126 | 363 / 1175 |
| LLM calls / tokens | 119 / {'prompt': 3535001, 'completion': 81686} | 119 / {'prompt': 3535440, 'completion': 84318} |
| Duration (s) | 419.5 | 430.3 |

| Similarity | Value |
|---|---|
| verdict_equal | True |
| techniques_jaccard | 0.286 |
| technique_families_jaccard | 0.625 |
| evidence_jaccard | 0.377 |
| planned_query_jaccard | 0.993 |
| coverage_cells_differing | 0 of 265 |
| ground_truth_equal | True |

Jaccard = |A∩B| / |A∪B| (1.0 = identical sets). Planned queries are compared after lower-casing and dropping size/fields/sort.

Only in 20261017-075714-converged-exp-B3-playbook (techniques): ['T1003.002', 'T1555.003', 'T1558.001']
Only in 20261017-075717-converged-exp-B4-playbook (techniques): ['T1003', 'T1056.001', 'T1056.004', 'T1212', 'T1552', 'T1552.004', 'T1555.004']
