#!/usr/bin/env bash
# Run the persistence security-lab scenario against the live monitor.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ -f .venv/bin/activate ]]; then
  # shellcheck source=/dev/null
  source .venv/bin/activate
fi
exec python -m runtime_engine.lab run --scenario persistence "$@"
