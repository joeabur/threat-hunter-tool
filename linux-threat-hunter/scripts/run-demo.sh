#!/usr/bin/env bash
# End-to-end demo on SYNTHETIC evidence. Read-only with respect to the host, no root, no network.
# Writes only inside ./.demo (created fresh each run).
set -euo pipefail
cd "$(dirname "$0")/.."
DEMO=".demo"
rm -rf -- "$DEMO"          # fixed relative path inside this repository, never user-supplied
mkdir -p "$DEMO"
LTH="${PYTHON:-python3} -m linux_threat_hunter"
export PYTHONPATH="${PYTHONPATH:-src}"
echo "== 1. validate rules";            $LTH rules validate
echo "== 2. baseline from clean synthetic evidence"
$LTH baseline create --input examples/synthetic-baseline-evidence --output "$DEMO/baseline.json"
echo "== 3. hunt synthetic incident evidence (IOCs + baseline)"
$LTH hunt --input examples/synthetic-evidence --iocs examples/iocs.json \
     --baseline "$DEMO/baseline.json" --output "$DEMO/results" --show 15
echo "== 4. reports"
$LTH report --input "$DEMO/results" --output "$DEMO/reports"
echo
echo "Demo complete. Open $DEMO/reports/summary.md and $DEMO/reports/findings.md"
echo "Remove generated files with: rm -rf .demo"
