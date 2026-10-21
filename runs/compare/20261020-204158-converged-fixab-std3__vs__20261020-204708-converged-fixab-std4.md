# Run comparison: 20261020-204158-converged-fixab-std3 vs 20261020-204708-converged-fixab-std4

Hypothesis: An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

| | 20261020-204158-converged-fixab-std3 | 20261020-204708-converged-fixab-std4 |
|---|---|---|
| Verdict | Confirmed | Confirmed |
| Ground truth sub-steps found (6.A/6.B/6.C) | 3/3 (6.A:yes, 6.B:yes, 6.C:yes) | 3/3 (6.A:yes, 6.B:yes, 6.C:yes) |
| Techniques with malicious/suspicious findings | T1003.001, T1003.004, T1056.002, T1212, T1539, T1552.001, T1552.002, T1552.004, T1557.002, T1649 | T1003.001, T1003.005, T1110.002, T1110.003, T1187, T1552.001, T1552.004, T1552.006, T1555.003, T1555.004, T1558, T1649 |
| Hosts implicated | bobs.bigwheel.local, nashua.dmevals.local, scranton.dmevals.local, simplerockbuild.simplerock.lan | bobs.bigwheel.local, nashua.dmevals.local, newyork.dmevals.local, scranton.dmevals.local, simplerockbuild.simplerock.lan |
| Findings (malicious+suspicious / all) | 25 / 61 | 26 / 64 |
| Incidents after consolidation | 12 | 18 |
| Verified evidence events | 65 | 63 |
| Rejected evidence items | 0 | 0 |
| Planned checks / all queries | 348 / 1297 | 337 / 1290 |
| LLM calls / tokens | 153 / {'prompt': 4628582, 'completion': 137359} | 156 / {'prompt': 4810507, 'completion': 129292} |
| Duration (s) | 620.4 | 610.0 |

| Similarity | Value |
|---|---|
| verdict_equal | True |
| techniques_jaccard | 0.222 |
| technique_families_jaccard | 0.273 |
| evidence_jaccard | 0.28 |
| planned_query_jaccard | 0.121 |
| coverage_cells_differing | 29 of 265 |
| ground_truth_equal | True |

Jaccard = |A∩B| / |A∪B| (1.0 = identical sets). Planned queries are compared after lower-casing and dropping size/fields/sort.

Only in 20261020-204158-converged-fixab-std3 (techniques): ['T1003.004', 'T1056.002', 'T1212', 'T1539', 'T1552.002', 'T1557.002']
Only in 20261020-204708-converged-fixab-std4 (techniques): ['T1003.005', 'T1110.002', 'T1110.003', 'T1187', 'T1552.006', 'T1555.003', 'T1555.004', 'T1558']
