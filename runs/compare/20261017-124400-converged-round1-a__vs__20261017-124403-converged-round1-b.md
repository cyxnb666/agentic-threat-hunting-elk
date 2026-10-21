# Run comparison: 20261017-124400-converged-round1-a vs 20261017-124403-converged-round1-b

Hypothesis: An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

| | 20261017-124400-converged-round1-a | 20261017-124403-converged-round1-b |
|---|---|---|
| Verdict | Confirmed | Confirmed |
| Ground truth sub-steps found (6.A/6.B/6.C) | 3/3 (6.A:yes, 6.B:yes, 6.C:yes) | 3/3 (6.A:yes, 6.B:yes, 6.C:yes) |
| Techniques with malicious/suspicious findings | T1003.001, T1003.006, T1187, T1552.001, T1552.004, T1555.004, T1558.001 | T1003, T1003.001, T1056.001, T1056.002, T1111, T1187, T1212, T1552.001, T1552.002, T1552.004, T1555, T1555.003, T1556, T1557, T1557.001, T1557.002, T1558, T1606, T1649 |
| Hosts implicated | nashua.dmevals.local, newyork.dmevals.local, scranton.dmevals.local, simplerockbuild.simplerock.lan | bobs.bigwheel.local, nashua.dmevals.local, scranton.dmevals.local, simplerockbuild.simplerock.lan |
| Findings (malicious+suspicious / all) | 23 / 65 | 33 / 68 |
| Incidents after consolidation | 12 | 23 |
| Verified evidence events | 52 | 70 |
| Rejected evidence items | 1 | 0 |
| Planned checks / all queries | 349 / 1383 | 349 / 1316 |
| LLM calls / tokens | 219 / {'prompt': 4505338, 'completion': 153337} | 146 / {'prompt': 4030000, 'completion': 137352} |
| Duration (s) | 700.5 | 600.5 |

| Similarity | Value |
|---|---|
| verdict_equal | True |
| techniques_jaccard | 0.182 |
| technique_families_jaccard | 0.417 |
| evidence_jaccard | 0.22 |
| planned_query_jaccard | 0.072 |
| coverage_cells_differing | 24 of 265 |
| ground_truth_equal | True |

Jaccard = |A∩B| / |A∪B| (1.0 = identical sets). Planned queries are compared after lower-casing and dropping size/fields/sort.

Only in 20261017-124400-converged-round1-a (techniques): ['T1003.006', 'T1555.004', 'T1558.001']
Only in 20261017-124403-converged-round1-b (techniques): ['T1003', 'T1056.001', 'T1056.002', 'T1111', 'T1212', 'T1552.002', 'T1555', 'T1555.003', 'T1556', 'T1557', 'T1557.001', 'T1557.002', 'T1558', 'T1606', 'T1649']
