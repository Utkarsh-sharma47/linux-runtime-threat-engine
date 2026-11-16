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
RULES=""
for line in "${PREP[@]}"; do
  case "$line" in
    session=*) SESSION="${line#session=}" ;;
    config=*) CONFIG="${line#config=}" ;;
    rules=*) RULES="${line#rules=}" ;;
    database=*) DB="${line#database=}" ;;
    export\ RTE_LAB_STATUS=*) STATUS="${line#export RTE_LAB_STATUS=}" ;;
  esac
done

if [[ -z "$SESSION" || -z "$CONFIG" || -z "$DB" ]]; then
  echo "error: failed to prepare lab session" >&2
  exit 1
fi

RULES="${RULES:-$SESSION/lab-rules.yaml}"
if [[ ! -f "$RULES" ]]; then
  echo "error: lab rules file missing: $RULES" >&2
  exit 1
fi

export RTE_LAB_ROOT="$SESSION"
export RTE_LAB_STATUS="${STATUS:-$SESSION/status.json}"
export RTE_LAB_DB="$DB"
export RTE_LAB_CONFIG="$CONFIG"
export RTE_LAB_RULES="$RULES"

mkdir -p "$(dirname "$DB")"
# Pid file used by the orchestrator as a liveness fallback.
echo $$ >"$(dirname "$DB")/monitor.pid"
# Replace this shell with the monitor so Ctrl+C / q stop cleanly.
# Lab-scoped rules + lab YAML keep ambient laptop /tmp apps and host listeners
# from creating incidents until you run a scenario.
exec python -m runtime_engine.main --config "$CONFIG" --db "$DB" --rules "$RULES" \
  monitor --include-cmdline
