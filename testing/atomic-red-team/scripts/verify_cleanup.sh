#!/usr/bin/env bash
# Read-only state snapshot and cleanup verification for one Atomic test run.
#
#   verify_cleanup.sh snapshot DIR                 record state before the test
#   verify_cleanup.sh verify DIR [--absent PATH]... compare after cleanup
#
# Persistence locations (crontab, shell startup files, SSH authorized_keys, user systemd
# units) must be unchanged: a change fails verification. Paths given with --absent must
# not exist. New entries in temporary directories are listed as warnings only, because
# other programs on the host also create files there.
set -euo pipefail

usage() { sed -n '2,10p' "$0"; exit 2; }

hash_file() { if [ -e "$1" ]; then sha256sum "$1" | cut -d' ' -f1; else echo absent; fi; }

take() {
  local dir=$1
  mkdir -p "$dir"
  chmod 700 "$dir"
  for tmp in /tmp /var/tmp /dev/shm; do
    find "$tmp" -mindepth 1 -maxdepth 1 -user "$(id -u)" -printf '%p\n' 2>/dev/null | sort
  done >"$dir/temp-entries.txt"
  {
    echo "crontab $( (crontab -l 2>/dev/null || true) | sha256sum | cut -d' ' -f1)"
    for f in ~/.bashrc ~/.profile ~/.bash_profile ~/.bash_logout ~/.zshrc ~/.ssh/authorized_keys; do
      echo "$f $(hash_file "$f")"
    done
    echo "systemd-user $(find ~/.config/systemd/user -type f 2>/dev/null | sort | sha256sum | cut -d' ' -f1)"
    echo "autostart $(find ~/.config/autostart -type f 2>/dev/null | sort | sha256sum | cut -d' ' -f1)"
  } >"$dir/persistence.txt"
}

[ $# -ge 2 ] || usage
command=$1
dir=$2
shift 2
case "$command" in
  snapshot)
    take "$dir/before"
    echo "snapshot written to $dir/before"
    ;;
  verify)
    [ -d "$dir/before" ] || { echo "FAIL no snapshot in $dir/before (run snapshot first)"; exit 2; }
    take "$dir/after"
    status=0
    if diff -u "$dir/before/persistence.txt" "$dir/after/persistence.txt" >"$dir/persistence.diff"; then
      echo "PASS persistence locations unchanged (crontab, shell rc files, authorized_keys, user units)"
    else
      echo "FAIL persistence locations changed:"
      grep '^[+-][^+-]' "$dir/persistence.diff" | sed 's/^/     /'
      status=1
    fi
    while [ $# -gt 0 ]; do
      case "$1" in
        --absent)
          [ $# -ge 2 ] || usage
          if [ -e "$2" ] || [ -L "$2" ]; then
            echo "FAIL $2 still exists"
            status=1
          else
            echo "PASS $2 does not exist"
          fi
          shift 2
          ;;
        *) usage ;;
      esac
    done
    new=$(comm -13 "$dir/before/temp-entries.txt" "$dir/after/temp-entries.txt" || true)
    if [ -n "$new" ]; then
      echo "WARN new entries owned by you in /tmp, /var/tmp or /dev/shm (may be unrelated):"
      echo "$new" | sed 's/^/     /'
    else
      echo "PASS no new entries owned by you in /tmp, /var/tmp or /dev/shm"
    fi
    exit $status
    ;;
  *) usage ;;
esac
