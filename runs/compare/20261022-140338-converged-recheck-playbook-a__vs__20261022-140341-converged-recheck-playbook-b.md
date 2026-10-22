# Run comparison: 20261022-140338-converged-recheck-playbook-a vs 20261022-140341-converged-recheck-playbook-b

Hypothesis: An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

| | 20261022-140338-converged-recheck-playbook-a | 20261022-140341-converged-recheck-playbook-b |
|---|---|---|
| Verdict | Confirmed | Confirmed |
| Ground truth sub-steps found (6.A/6.B/6.C) | 3/3 (6.A:yes, 6.B:yes, 6.C:yes) | 3/3 (6.A:yes, 6.B:yes, 6.C:yes) |
| Techniques with malicious/suspicious findings | T1003.001, T1056, T1056.001, T1056.002, T1187, T1552, T1552.001, T1552.004, T1552.006, T1555, T1555.004, T1556, T1606.002, T1649 | T1003.001, T1056.001, T1187, T1212, T1552, T1552.001, T1555.003, T1558, T1606.002, T1649 |
| Hosts implicated | bobs.bigwheel.local, nashua.dmevals.local, scranton.dmevals.local, simplerockbuild.simplerock.lan | nashua.dmevals.local, newyork.dmevals.local, scranton.dmevals.local, simplerockbuild.simplerock.lan |
| Findings (malicious+suspicious / all) | 27 / 69 | 25 / 65 |
| Incidents after consolidation | 15 | 17 |
| Verified evidence events | 50 | 55 |
| Rejected evidence items | 2 | 0 |
| Planned checks / all queries | 363 / 1348 | 363 / 1292 |
| LLM calls / tokens | 163 / {'prompt': 5398926, 'completion': 119839} | 150 / {'prompt': 4326094, 'completion': 97495} |
| Duration (s) | 630.3 | 530.8 |

| Similarity | Value |
|---|---|
| verdict_equal | True |
| techniques_jaccard | 0.412 |
| technique_families_jaccard | 0.7 |
| evidence_jaccard | 0.4 |
| planned_query_jaccard | 1.0 |
| coverage_cells_differing | 0 of 265 |
| ground_truth_equal | True |

Jaccard = |A∩B| / |A∪B| (1.0 = identical sets). Planned queries are compared after lower-casing and dropping size/fields/sort.

Only in 20261022-140338-converged-recheck-playbook-a (techniques): ['T1056', 'T1056.002', 'T1552.004', 'T1552.006', 'T1555', 'T1555.004', 'T1556']
Only in 20261022-140341-converged-recheck-playbook-b (techniques): ['T1212', 'T1555.003', 'T1558']
