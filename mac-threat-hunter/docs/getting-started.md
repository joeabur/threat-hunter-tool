# Getting started

## Prerequisites

- Python 3.11 or newer (`python3 --version`), `git`, and `pip`.
- Any of macOS, Linux or Windows for analysis and the synthetic demo. Live collection needs macOS.
- No root, no Full Disk Access, and no network access beyond the one-time `pip install`.

## Install from a fresh clone

```bash
git clone https://github.com/joeabur/threat-hunter-tool.git
cd threat-hunter-tool/mac-threat-hunter
python3 -m venv .venv
source .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

`scripts/setup-dev.sh` does the same on macOS/Linux. The only runtime dependency is PyYAML
(`>=6,<7`); development tools (pytest, ruff, mypy, jsonschema, build, bandit, pip-audit) are in
the `dev` extra. For fully reproducible installs, pin with `pip freeze > requirements.lock` after
a known-good install and install from that file in CI.

## Verify

```bash
python -m mac_threat_hunter doctor      # environment + config + rules
python -m mac_threat_hunter rules validate
python -m pytest -q                     # macOS-only tests are skipped elsewhere
bash scripts/run-demo.sh                # synthetic end-to-end run (writes ./demo-output)
```

Next: the [walkthrough](walkthrough.md).
