#!/usr/bin/env bash
# Fully synthetic end-to-end demo. Runs on Linux, macOS or Windows (Git Bash/WSL) without root,
# network access, a Mac, or any live collection. Writes only under ./demo-output.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

PY="${PYTHON:-python}"
MTH=("$PY" -m mac_threat_hunter)
OUT="${DEMO_OUT:-demo-output}"

rm -rf "$OUT"
mkdir -p "$OUT"

echo "== 1. Environment check"
"${MTH[@]}" doctor

echo
echo "== 2. Validate detection rules"
"${MTH[@]}" rules validate

echo
echo "== 3. Hunt the SYNTHETIC evidence with synthetic IOCs and a synthetic baseline"
"${MTH[@]}" hunt \
  --input examples/synthetic-evidence \
  --iocs examples/iocs.json \
  --baseline examples/baselines/clean-baseline.json \
  --output "$OUT/results"

echo
echo "== 4. Render reports"
"${MTH[@]}" report --input "$OUT/results" --output "$OUT/reports"

echo
echo "== 5. Compare rule hits with examples/expected-results/expected-rule-hits.json"
"$PY" - "$OUT/results/results.json" <<'PYEOF'
import json
import sys
from collections import Counter

results = json.load(open(sys.argv[1], encoding="utf-8"))
expected = json.load(open("examples/expected-results/expected-rule-hits.json", encoding="utf-8"))
actual = dict(sorted(Counter(f["rule_id"] for f in results["findings"]).items()))
if actual != expected["rule_hits"]:
    print("MISMATCH between actual and expected rule hits")
    for rule in sorted(set(actual) | set(expected["rule_hits"])):
        if actual.get(rule) != expected["rule_hits"].get(rule):
            print(f"  {rule}: actual={actual.get(rule)} expected={expected['rule_hits'].get(rule)}")
    sys.exit(1)
print(f"OK: {len(results['findings'])} findings across {len(actual)} rules match the expected results")
PYEOF

echo
echo "Demo complete. Outputs (synthetic data only): $OUT/results/results.json and $OUT/reports/"
