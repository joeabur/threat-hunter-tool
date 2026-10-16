#!/usr/bin/env bash
# Create a virtual environment and install mac-threat-hunter with development tools.
# Needs Python 3.11+ and network access to PyPI for the dependency download only.
# Nothing here needs root, and no tool in this project invokes sudo.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

PYTHON="${PYTHON:-python3}"
if ! "$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "error: Python 3.11 or newer is required (set PYTHON=/path/to/python3.12 to choose one)." >&2
  exit 1
fi

"$PYTHON" -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

echo
echo "Done. Activate the environment with:  source .venv/bin/activate"
echo "Then try:                              python -m mac_threat_hunter doctor"
