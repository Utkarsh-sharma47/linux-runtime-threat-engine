#!/usr/bin/env bash
# Read-only readiness checks for the Atomic Red Team lab. Executes no Atomic test.
#
#   preflight.sh [--db ENGINE_DB] [--snapshot DIR]
#
# --db        also require a live monitor session writing to ENGINE_DB
# --snapshot  record pre-test state for verify_cleanup.sh in DIR
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
python="$repo/.venv/bin/python"
atomics="${ATOMICS_PATH:-$HOME/AtomicRedTeam/atomics}"
db=""
snapshot=""
while [ $# -gt 0 ]; do
  case "$1" in
    --db) db=$2; shift 2 ;;
    --snapshot) snapshot=$2; shift 2 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

fail=0
pass() { echo "PASS $*"; }
warn() { echo "WARN $*"; }
bad() { echo "FAIL $*"; fail=1; }

if [ "$(id -u)" -eq 0 ]; then
  bad "running as root; run the lab as a normal user"
else
  pass "running as $(id -un) (uid $(id -u)), not root"
fi

if command -v pwsh >/dev/null; then
  pass "pwsh $(pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()') at $(command -v pwsh)"
  modules=$(pwsh -NoProfile -Command '(Get-Module -ListAvailable invoke-atomicredteam,powershell-yaml | % { $_.Name + " " + $_.Version }) -join "; "')
  if echo "$modules" | grep -qi "invoke-atomicredteam" && echo "$modules" | grep -qi "powershell-yaml"; then
    pass "PowerShell modules: $modules"
  else
    bad "Invoke-AtomicRedTeam or powershell-yaml module missing (found: ${modules:-none})"
  fi
else
  bad "pwsh not found on PATH (see install.md)"
fi

if [ -d "$atomics" ]; then
  commit=$(git -C "$atomics/.." rev-parse --short HEAD 2>/dev/null || echo unknown)
  pass "atomics folder $atomics ($(find "$atomics" -maxdepth 2 -name 'T*.yaml' | wc -l) technique files, commit $commit)"
else
  bad "atomics folder not found: $atomics"
fi

if [ -x "$python" ] && "$python" -c 'import runtime_engine, yaml' 2>/dev/null; then
  pass "engine virtual environment $python"
else
  bad "engine virtual environment missing or incomplete: $python"
fi

avail=$(df -Pk "$HOME" | awk 'NR==2 {print $4}')
if [ "$avail" -gt 1048576 ]; then
  pass "free disk space $((avail / 1024)) MiB"
else
  warn "less than 1 GiB free disk space"
fi

if [ -n "$db" ]; then
  if status=$("$python" "$here/atomic_report.py" engine-status --db "$db"); then
    pass "engine running: $status"
  else
    bad "engine not running for $db: $status"
  fi
else
  warn "no --db given: engine status not checked"
fi

if [ -n "$snapshot" ]; then
  "$here/verify_cleanup.sh" snapshot "$snapshot" >/dev/null && pass "pre-test state snapshot in $snapshot/before"
fi

exit $fail
