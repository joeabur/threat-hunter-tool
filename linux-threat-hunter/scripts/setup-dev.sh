#!/usr/bin/env bash
# Create a virtual environment and install the project with development tools.
# Needs only Python 3.11+ and network access to PyPI for pip. No root required.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
"$PY" -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ required"'
"$PY" -m venv .venv
# shellcheck disable=SC1091
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
python -m pip install -e . --no-deps
echo "Done. Activate with: source .venv/bin/activate"
