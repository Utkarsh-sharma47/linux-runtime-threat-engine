#!/usr/bin/env bash
# Start the live EDR dashboard pointed at an isolated security-lab session.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if [[ -f .venv/bin/activate ]]; then
  # shellcheck source=/dev/null
  source .venv/bin/activate
fi

echo "Preparing security-lab session..."
mapfile -t PREP < <(python -m runtime_engine.lab prepare | tee /dev/stderr)
SESSION=""
CONFIG=""
DB=""
STATUS=""
for line in "${PREP[@]}"; do
  case "$line" in
    session=*) SESSION="${line#session=}" ;;
    config=*) CONFIG="${line#config=}" ;;
    database=*) DB="${line#database=}" ;;
    export\ RTE_LAB_STATUS=*) STATUS="${line#export RTE_LAB_STATUS=}" ;;
  esac
done

if [[ -z "$SESSION" || -z "$CONFIG" || -z "$DB" ]]; then
  echo "error: failed to prepare lab session" >&2
  exit 1
fi

export RTE_LAB_ROOT="$SESSION"
export RTE_LAB_STATUS="${STATUS:-$SESSION/status.json}"
export RTE_LAB_DB="$DB"
export RTE_LAB_CONFIG="$CONFIG"

mkdir -p "$(dirname "$DB")"
# Pid file used by the orchestrator as a liveness fallback.
echo $$ >"$(dirname "$DB")/monitor.pid"
# Replace this shell with the monitor so Ctrl+C / q stop cleanly.
# Security modules are ON by default; lab YAML points them at the temp lab tree.
exec python -m runtime_engine.main --config "$CONFIG" --db "$DB" monitor --include-cmdline
