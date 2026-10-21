# Run comparison: 20261017-081620-converged-final-full vs 20261017-081623-converged-final-playbook

Hypothesis: An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

| | 20261017-081620-converged-final-full | 20261017-081623-converged-final-playbook |
|---|---|---|
| Verdict | Confirmed | Confirmed |
| Ground truth sub-steps found (6.A/6.B/6.C) | 2/3 (6.A:no, 6.B:yes, 6.C:yes) | 3/3 (6.A:yes, 6.B:yes, 6.C:yes) |
| Techniques with malicious/suspicious findings | T1003, T1003.001, T1056.001, T1056.002, T1187, T1552, T1552.001, T1552.004 | T1003, T1003.001, T1003.002, T1056.004, T1187, T1552.001, T1552.004, T1558.001, T1558.003 |
| Hosts implicated | nashua.dmevals.local, scranton.dmevals.local, simplerockbuild.simplerock.lan | nashua.dmevals.local, newyork.dmevals.local, scranton.dmevals.local, simplerockbuild.simplerock.lan |
| Findings (malicious+suspicious / all) | 16 / 56 | 24 / 63 |
| Incidents after consolidation | 10 | 13 |
| Verified evidence events | 31 | 40 |
| Rejected evidence items | 1 | 1 |
| Planned checks / all queries | 343 / 1061 | 363 / 1181 |
| LLM calls / tokens | 128 / {'prompt': 3307343, 'completion': 107521} | 132 / {'prompt': 3410426, 'completion': 86480} |
| Duration (s) | 565.7 | 486.0 |

| Similarity | Value |
|---|---|
| verdict_equal | True |
| techniques_jaccard | 0.417 |
| technique_families_jaccard | 0.8 |
| evidence_jaccard | 0.224 |
| planned_query_jaccard | 0.076 |
| coverage_cells_differing | 8 of 265 |
| ground_truth_equal | False |

Jaccard = |A∩B| / |A∪B| (1.0 = identical sets). Planned queries are compared after lower-casing and dropping size/fields/sort.

Only in 20261017-081620-converged-final-full (techniques): ['T1056.001', 'T1056.002', 'T1552']
Only in 20261017-081623-converged-final-playbook (techniques): ['T1003.002', 'T1056.004', 'T1558.001', 'T1558.003']
