#!/usr/bin/env bash
# Safely remove the active security-lab session (confirmation required).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if [[ -f .venv/bin/activate ]]; then
  # shellcheck source=/dev/null
  source .venv/bin/activate
fi

exec python -m runtime_engine.lab cleanup "$@"
