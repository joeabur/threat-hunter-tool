# Examples

All examples use bundled **synthetic** data; run from `mac-threat-hunter/`.

```bash
# Full demo (hunt + reports + comparison with expected results)
bash scripts/run-demo.sh

# Clean host: zero findings (false-positive control)
python -m mac_threat_hunter hunt --input examples/synthetic-evidence-clean

# Suspicious host with IOCs and a baseline
python -m mac_threat_hunter hunt --input examples/synthetic-evidence \
  --iocs examples/iocs.json --baseline examples/baselines/clean-baseline.json \
  --output demo-output/results

# Reports in all formats, and failing a pipeline on high severity
python -m mac_threat_hunter report --input demo-output/results --output demo-output/reports --formats md,json,csv
python -m mac_threat_hunter hunt --input examples/synthetic-evidence --fail-on high --quiet; echo $?   # 1

# What would a live collection do? (writes nothing)
python -m mac_threat_hunter collect --profile full --dry-run
```

## Layout

| Path | Contents |
| --- | --- |
| `examples/synthetic-evidence/` | Suspicious host, 53 records, with decoys and benign controls |
| `examples/synthetic-evidence-clean/` | Benign host; expected to produce no findings |
| `examples/iocs.json` | 7 synthetic indicators, 2 of them decoys that must not match |
| `examples/baselines/clean-baseline.json` | Baseline of the clean host |
| `examples/expected-results/expected-rule-hits.json` | Expected findings per rule (checked by tests and the demo) |

Regenerate with `scripts/generate_synthetic_evidence.py` and `scripts/update_expected_results.py`
when changing rules. For step-by-step practice see the [walkthrough](walkthrough.md).
