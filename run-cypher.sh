#!/usr/bin/env bash
# Launch the Cypher UI on Linux/Kali. Double-click (mark executable) or run ./run-cypher.sh
set -e
cd "$(dirname "$0")"

if [ ! -x ".venv/bin/python" ]; then
  echo "First-time setup: creating virtual environment..."
  python3 -m venv .venv
  ./.venv/bin/python -m pip install --upgrade pip
  ./.venv/bin/python -m pip install -e ".[all]"
fi

echo "Starting Cypher UI at http://127.0.0.1:8765 ..."
exec ./.venv/bin/python -m cypher.web
