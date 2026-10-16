# Getting started

This page takes you from a fresh clone to a working install and a first hunt. No root privileges and no network access (beyond installing packages with pip) are needed.

## Prerequisites

- Python 3.11 or newer (`python3 --version`).
- `git`, and `pip` (bundled with Python).
- Linux, macOS or Windows for analysis and tests. **Live collection requires Linux.**

What has been verified: the full test suite, linting, type checking, rule validation and the demo script were run during development on Ubuntu 24.04 with Python 3.13. CI is configured to run the portable suite on Linux, macOS and Windows with Python 3.11-3.13; check the workflow results for your platform.

## Install

```bash
git clone <this repository>
cd threat-hunter-tool/linux-threat-hunter
python3 -m venv .venv
source .venv/bin/activate            # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
python -m pip install -e . --no-deps
```

`requirements-dev.txt` pins the development toolchain. The only runtime dependency is PyYAML (plus `tzdata` on Windows). Alternatively run `bash scripts/setup-dev.sh`.

## Verify

```bash
python -m pytest -q
python -m linux_threat_hunter info
python -m linux_threat_hunter doctor
python -m linux_threat_hunter rules validate
```

Expected: tests pass, `rules validate` prints `33 rule(s) valid, 0 problem(s)`, and `doctor` ends with `ready (warnings are informational)`. Warnings (for example a missing `ss` tool) describe collectors that will be partial or skipped on this machine.

## First hunt on synthetic data

```bash
python -m linux_threat_hunter hunt --input examples/synthetic-evidence --iocs examples/iocs.json --output ./results
python -m linux_threat_hunter report --input ./results --output ./reports
```

Open `reports/summary.md`. The synthetic evidence is invented training data; see the [walkthrough](walkthrough.md) for guided exercises.

## First live collection (Linux, authorized hosts only)

```bash
python -m linux_threat_hunter collect --profile basic --output ./evidence --dry-run   # shows the plan, touches nothing
python -m linux_threat_hunter collect --profile basic --output ./evidence
python -m linux_threat_hunter hunt --input ./evidence --output ./results
```

Run it as the account you are authorized to use. The tool never calls `sudo`. If a collector cannot read something, it records the reason and continues; the report lists it under *Missing telemetry*. Evidence can contain sensitive data: keep `./evidence` private (see [security and limitations](security-and-limitations.md)).

## Where to go next

[Walkthrough](walkthrough.md) · [User guide](user-guide.md) · [Rule authoring](rule-authoring.md) · [Configuration](configuration.md) · [Troubleshooting](troubleshooting.md)
