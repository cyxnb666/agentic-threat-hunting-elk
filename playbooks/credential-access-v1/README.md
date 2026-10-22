# Playbook credential-access-v1

Frozen framing (01_frame.json) and coverage plan (02_plan.json: 363 checks over 53 ATT&CK v20.0
credential-access techniques x 5 datasets) produced by the converged hunt agent in run 20261017-010833-converged-exp-B1
(run folders are not in the repository any more; that one is in the git history, commit 3efed3a, under runs/hunts/).
Use it with: python -m hunt hunt "<hypothesis>" --profile converged --plan-from playbooks/credential-access-v1
Runs that use the same playbook execute exactly the same planned queries; only triage/pivot are re-done by the LLM.
