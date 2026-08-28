#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

if [ ! -x ".venv/bin/python" ]; then
  echo "First-time setup: creating virtual environment..."
  python3 -m venv .venv
  ./.venv/bin/python -m pip install --upgrade pip
  ./.venv/bin/python -m pip install -e ".[all]"
fi

[ -f .env ] || echo "CYPHER_LLM=cli" > .env

if ! command -v claude >/dev/null 2>&1; then
  echo ""
  echo "  NOTE: AI chat and briefings run on your Claude subscription via Claude Code."
  echo "  Install it and run 'claude' once to log in, then it's free, no credits."
  echo "  Scans, graph and profile cards work now without it."
  echo ""
fi

echo "Starting Cypher UI at http://127.0.0.1:8765 ..."
exec ./.venv/bin/python -m cypher.web
