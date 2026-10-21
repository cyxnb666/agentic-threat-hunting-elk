# Run comparison: 20261017-084130-converged-final3-full vs 20261017-084133-converged-final3-playbook

Hypothesis: An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

| | 20261017-084130-converged-final3-full | 20261017-084133-converged-final3-playbook |
|---|---|---|
| Verdict | Confirmed | Confirmed |
| Ground truth sub-steps found (6.A/6.B/6.C) | 3/3 (6.A:yes, 6.B:yes, 6.C:yes) | 3/3 (6.A:yes, 6.B:yes, 6.C:yes) |
| Techniques with malicious/suspicious findings | T1003.001, T1552.001, T1552.004, T1557.001, T1557.002 | T1003.001, T1187, T1552.001, T1552.004, T1555.003, T1557.001, T1557.002 |
| Hosts implicated | nashua.dmevals.local, scranton.dmevals.local, simplerockbuild.simplerock.lan | bobs.bigwheel.local, nashua.dmevals.local, scranton.dmevals.local, simplerockbuild.simplerock.lan |
| Findings (malicious+suspicious / all) | 24 / 61 | 25 / 67 |
| Incidents after consolidation | 14 | 17 |
| Verified evidence events | 33 | 39 |
| Rejected evidence items | 1 | 2 |
| Planned checks / all queries | 337 / 1058 | 363 / 1162 |
| LLM calls / tokens | 123 / {'prompt': 3190527, 'completion': 108879} | 127 / {'prompt': 3284224, 'completion': 81996} |
| Duration (s) | 587.0 | 483.6 |

| Similarity | Value |
|---|---|
| verdict_equal | True |
| techniques_jaccard | 0.714 |
| technique_families_jaccard | 0.6 |
| evidence_jaccard | 0.358 |
| planned_query_jaccard | 0.093 |
| coverage_cells_differing | 10 of 265 |
| ground_truth_equal | True |

Jaccard = |A∩B| / |A∪B| (1.0 = identical sets). Planned queries are compared after lower-casing and dropping size/fields/sort.

Only in 20261017-084130-converged-final3-full (techniques): []
Only in 20261017-084133-converged-final3-playbook (techniques): ['T1187', 'T1555.003']
