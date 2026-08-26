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

# Default to subscription mode (free — uses the Claude CLI, no API credits).
[ -f .env ] || echo "CYPHER_LLM=cli" > .env

# Check the Claude CLI (needed for AI on your subscription).
if ! command -v claude >/dev/null 2>&1; then
  echo ""
  echo "  NOTE: AI (chat + briefings) runs on your Claude subscription via Claude Code."
  echo "  Install it and run 'claude' once to log in — then it's free, no credits."
  echo "  Scans, graph and profile cards work right now without it."
  echo ""
fi

echo "Starting Cypher UI at http://127.0.0.1:8765 ..."
exec ./.venv/bin/python -m cypher.web
