# Troubleshooting

## Installation

| Problem | Cause / fix |
|---|---|
| `No module named linux_threat_hunter` | activate the virtualenv and run `python -m pip install -e . --no-deps`, or run from the project directory with `export PYTHONPATH=src` |
| `requires a different Python` | Python 3.11+ is required (`python3 --version`) |
| `No module named yaml` | `python -m pip install -r requirements-dev.txt` (PyYAML is the only runtime dependency) |
| `rules directory not found` | run from `linux-threat-hunter/`, pass `--rules-dir rules`, or set `LTH_RULES_DIR`. A wheel install bundles rules as `linux_threat_hunter/_rules` |
| Timezone names not recognized on Windows | install `tzdata` (a dependency on Windows); unknown names fall back to UTC and the report says `UTC` |

## Permissions and missing telemetry

The tool never escalates privileges. When a collector cannot read something it records why and continues; see *Missing telemetry* in `summary.md` and `collectors` in `manifest.json`.

| Symptom | Meaning |
|---|---|
| `process: partial ... attributes were not readable` | `/proc/<pid>/exe` of other users' processes needs elevated read access. Run as the authorized account you need (for example under your organization's approved process); the tool will not do it for you |
| `auth: failed ... no readable auth log` | `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (Fedora/RHEL) is not readable and `journalctl` returned nothing. Membership in `adm` or `systemd-journal` (or equivalent) is usually what grants read access |
| `network: failed ... ss unavailable` | install `iproute2` yourself; the tool never installs anything |
| process-to-socket links missing | socket owners are only visible for your own processes without privileges; rules needing them (`LTH-NET-003`, correlation by pid) cannot fire |
| rules `skipped` | the report names the reason: missing telemetry, no `--iocs`, no `--baseline`, or disabled in config |
| containers | `/proc` shows the container's namespace only; the host cannot be inferred from inside a container |
| auth events without timestamps | syslog timestamps need a valid month/day/time; unparseable lines are counted in the report and excluded from threshold rules |

## Parsing problems

- **Wrong years or hours in syslog timestamps.** Syslog lines have no year or zone. The year is inferred from the evidence's `collected_at` (a date more than a day in the future is moved to the previous year) and the zone comes from the manifest `timezone`. Set both correctly when importing evidence by hand. Findings keep the original `raw_timestamp`.
- **Unsupported log lines** are ignored and counted (`trace --ref auth.log#N` errors for unparsed lines).
- **Malformed evidence JSON** produces a warning and that source is treated as unavailable; other sources still run.
- **Symlinked evidence files are refused** (safety measure). Copy the real files into the evidence directory.
- **Hash mismatch warning**: a file differs from the SHA-256 recorded in `manifest.json` at collection. Treat the evidence as modified until explained.

## CLI errors

| Message | Fix |
|---|---|
| `error: ... evidence directory not found` (exit 2) | check `--input` |
| `error: IOC file error: ...` (exit 2) | see the message; hashes need 64 hex characters, domains need valid ASCII names, paths must be absolute |
| `error: configuration error: ...` (exit 2) | fix the named key; unknown keys are rejected |
| `rule validation failed` (exit 2) | run `rules validate` for details |
| `baselines are never replaced silently` | choose a new file, or `baseline update --approve` / `baseline create --force` |
| `integrity_sha256 mismatch` | the baseline was edited or corrupted; recreate it from trusted evidence |
| `refusing to write through a symlink` | choose a normal output directory |
| `no findings match the given filters` (`show`) | that rule did not fire in this run (it may have been skipped) |

## Tests and CI

- Tests marked Linux-only skip on other systems. Subprocess tests for `sleep`/`seq` skip on Windows.
- If `pytest` imports the installed package instead of your edits, reinstall in editable mode (`pip install -e . --no-deps`).
- Packaging check: `python -m build` then install the wheel in a clean virtualenv and run `linux-threat-hunter rules validate`.
- The non-Linux CI legs are marked `continue-on-error` until they have a recorded green run; do not rely on them as proof of support.
