# Contributing

Thanks for helping. This is a security tool, so the bar for safety and honesty is high.

## Ground rules

1. **Read-only.** No change may kill processes, modify services, users, files or firewall rules, invoke `sudo`, or execute discovered content. A test (`test_read_only_guarantee_no_remediation_code`) greps the package for forbidden calls.
2. **No shell with untrusted input.** Use argv lists via `utils.safe.run_command` (timeout + output limit).
3. **Declarative rules only.** Rules are data validated by `rules_engine/schema.py`. Do not add features that evaluate code from rules, events or logs.
4. **Honest claims.** Every rule needs a rationale, false-positive guidance, investigation steps and, where justified, an ATT&CK mapping. Do not map techniques the behavior does not support. Do not write wording that says a finding proves compromise.
5. **Synthetic data only.** Never commit real logs, hostnames, credentials, customer evidence or threat-intel feeds. Use documentation address ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and `.example`/`.test` names.

## Setup and checks

```bash
bash scripts/setup-dev.sh && source .venv/bin/activate
ruff check . && ruff format --check .
mypy
python -m pytest -q
python -m linux_threat_hunter rules validate
bash scripts/run-demo.sh
```

## Adding a rule

Read [docs/rule-authoring.md](docs/rule-authoring.md). Add the YAML under `rules/<area>/`, a test (including a false-positive scenario), a synthetic evidence case if useful (then update `examples/expected-results/expected-findings.json`), and a row in [docs/detection-coverage.md](docs/detection-coverage.md) (a test fails if a rule ID is undocumented).

## Pull requests

Describe what changed and why, list the checks you ran, and note anything you could not run. Keep documentation consistent with behavior; a test checks that documented commands parse and relative links resolve.
