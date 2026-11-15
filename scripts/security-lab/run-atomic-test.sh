#!/usr/bin/env bash
# Interactive Atomic Red Team profile picker (approval-gated; not part of --scenario all).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ -f .venv/bin/activate ]]; then
  # shellcheck source=/dev/null
  source .venv/bin/activate
fi
exec python -m runtime_engine.lab.atomic_menu "$@"
