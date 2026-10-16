# Contributing

Thanks for helping. This is a defensive, read-only tool; contributions must keep it that way.

## Ground rules

- No code that executes discovered files, uses `sudo`, shells out via a shell, writes outside
  the chosen output directory, or makes network calls at runtime.
- New detections are **YAML rules** first (see [docs/rule-authoring.md](docs/rule-authoring.md)).
  Every rule needs a description, severity and confidence, a justified ATT&CK mapping,
  false positives, investigation steps, and tests/synthetic evidence that trigger it **and**
  a benign case that does not.
- Use only synthetic data (`.example.test`, documentation IP ranges, fabricated hashes).
  Never commit real evidence, credentials, or host data.
- Do not overstate: no claims of detecting all malware or replacing an EDR.

## Setup and checks

```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -e ".[dev]"
ruff format . && ruff check . && mypy src
python -m mac_threat_hunter rules validate
python -m pytest -q
python scripts/gen_coverage.py          # regenerate docs/detection-coverage.md
python scripts/update_expected_results.py   # only if rule hits intentionally changed
bash scripts/run-demo.sh
```

Optional: `pre-commit install` (see `.pre-commit-config.yaml`).

## Pull requests

Keep PRs focused, explain what changed and why, note what you tested (and what you could not,
e.g. no macOS access), and update docs and `CHANGELOG.md`. By contributing you agree your work
is licensed under the MIT license.
