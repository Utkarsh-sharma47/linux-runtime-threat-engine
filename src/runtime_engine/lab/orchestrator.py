"""Run security-lab scenarios against a live monitor session."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any

from runtime_engine.lab.paths import (
    ENV_DB,
    ENV_STATUS,
    LabPathError,
    resolve_active_session,
    status_path,
    validate_under_lab_root,
)
from runtime_engine.lab.scenarios import SAFE_ALL, SCENARIOS
from runtime_engine.lab.session import env_exports, prepare_session
from runtime_engine.lab.status import LabStatus, now_iso, read_status, write_status


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="run-security-lab",
        description="One-command EDR demonstration scenarios (safe fixtures + real telemetry).",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        dest="scenarios",
        metavar="NAME",
        help="Scenario to run (repeatable). Use 'all' for the safe default set.",
    )
    parser.add_argument("--list", action="store_true", help="List available scenarios and exit")
    parser.add_argument(
        "--dry-run", action="store_true", help="Show what would run without executing"
    )
    parser.add_argument(
        "--skip-monitor-check",
        action="store_true",
        help="Do not require a live monitor (for dry-run / unit tests)",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Repository root (defaults to cwd)",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable summary")
    return parser.parse_args(argv)


def list_scenarios() -> list[tuple[str, str]]:
    descriptions = {
        "process": "Temp-dir process + ancestry (RT002)",
        "network": "Local HTTP + shell→curl (RT005, network module)",
        "persistence": "Lab cron/systemd/SUID fixtures (persistence module)",
        "integrity": "Merkle create/modify/delete (integrity module)",
        "exposure": "Unexpected lab SUID (exposure module)",
        "anomaly": "Report UNTRAINED/TRAINED honestly (anomaly module)",
        "ransomware": "Safe ransomware simulator (RW001)",
        "atomic": "Inspect Atomic test; run only with RTE_LAB_ATOMIC_APPROVE",
        "all": "Safe set: " + ", ".join(SAFE_ALL),
    }
    return [(name, descriptions.get(name, "")) for name in list(SCENARIOS) + ["all"]]


def resolve_scenario_names(requested: list[str] | None) -> list[str]:
    names = requested or ["all"]
    out: list[str] = []
    for name in names:
        key = name.lower().strip()
        if key == "all":
            out.extend(SAFE_ALL)
            continue
        if key not in SCENARIOS:
            raise SystemExit(f"unknown scenario {name!r}; use --list")
        out.append(key)
    # Preserve order, drop duplicates
    seen: set[str] = set()
    ordered: list[str] = []
    for name in out:
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    return ordered


def monitor_running(database: Path) -> tuple[bool, str]:
    """Best-effort check: SQLite monitor_sessions has a RUNNING body, or WAL activity."""
    if not database.exists():
        return False, f"database not found: {database}"
    try:
        conn = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=2)
    except sqlite3.Error as exc:
        return False, f"cannot open database: {exc}"
    try:
        rows = conn.execute(
            "SELECT id, body FROM monitor_sessions ORDER BY rowid DESC LIMIT 5"
        ).fetchall()
    except sqlite3.Error as exc:
        conn.close()
        return False, f"monitor_sessions unavailable: {exc}"
    finally:
        conn.close()
    for _sid, body in rows:
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            continue
        if data.get("status") == "RUNNING":
            return True, f"session {data.get('session_id', _sid)} RUNNING"
    # Fallback: process holding the DB — check for our start-monitor pid file.
    pid_file = database.parent / "monitor.pid"
    if pid_file.is_file():
        try:
            pid = int(pid_file.read_text(encoding="utf-8").strip())
            os.kill(pid, 0)
            return True, f"monitor pid {pid} alive ({pid_file.name})"
        except (ValueError, OSError):
            pass
    return False, "no RUNNING monitor session found — start ./scripts/start-monitor.sh first"


def run_lab(args: argparse.Namespace) -> int:
    if args.list:
        for name, desc in list_scenarios():
            print(f"  {name:12}  {desc}")
        return 0

    repo = args.repo_root or Path.cwd()
    names = resolve_scenario_names(args.scenarios)
    session = resolve_active_session()
    if session is None:
        if args.dry_run or args.skip_monitor_check:
            session, config, _ransom, status = prepare_session(repo_root=repo)
            print(f"prepared lab session {session} (no active session found)", file=sys.stderr)
        else:
            print(
                "error: no active lab session. Run ./scripts/start-monitor.sh first.",
                file=sys.stderr,
            )
            return 2
    else:
        session = validate_under_lab_root(session)
        status = read_status(status_path(session)) or LabStatus(
            session_id=session.name, lab_dir=str(session), database=str(session / "monitor.db")
        )
        config = session / "monitor.yaml"

    os.environ.update(env_exports(session, config if config.exists() else session / "monitor.yaml"))
    database = Path(os.environ.get(ENV_DB, status.database or session / "monitor.db"))

    if not args.dry_run and not args.skip_monitor_check:
        ok, reason = monitor_running(database)
        if not ok:
            print(f"error: monitor not ready ({reason})", file=sys.stderr)
            return 3
        status.collector_health = {"monitor": reason, "database": str(database)}

    status.phase = "running"
    status.updated_at = now_iso()
    status.message = f"Running scenarios: {', '.join(names)}"
    write_status(status)

    summary: dict[str, Any] = {
        "session_id": status.session_id or session.name,
        "lab_dir": str(session),
        "database": str(database),
        "dry_run": args.dry_run,
        "scenarios": [],
    }

    try:
        for name in names:
            print(f"\n=== scenario: {name} ===")
            status.current_scenario = name
            status.scenario_started_at = now_iso()
            status.updated_at = now_iso()
            write_status(status)
            runner = SCENARIOS[name]
            result = runner(session, status, args.dry_run)
            status.scenarios[name] = result.as_dict()
            status.updated_at = now_iso()
            write_status(status)
            summary["scenarios"].append(result.as_dict())
            for line in result.behavior:
                print(f"  behavior: {line}")
            for line in result.notes:
                print(f"  note: {line}")
            print(f"  status: {result.status}")
            print(f"  provenance: {', '.join(result.provenance)}")
            # Brief settle time between scenarios for collectors.
            if not args.dry_run:
                time.sleep(1.0)
        status.phase = "completed"
        status.current_scenario = None
        status.message = "All requested scenarios finished. Investigate the live dashboard."
    except KeyboardInterrupt:
        status.phase = "interrupted"
        status.message = "Interrupted by operator"
        write_status(status)
        print("interrupted", file=sys.stderr)
        return 130
    except LabPathError as exc:
        status.phase = "failed"
        status.message = str(exc)
        write_status(status)
        print(f"error: {exc}", file=sys.stderr)
        return 4
    except Exception as exc:
        status.phase = "failed"
        status.message = f"{type(exc).__name__}: {exc}"
        write_status(status)
        raise
    finally:
        status.updated_at = now_iso()
        write_status(status)
        evidence = session / "evidence" / "summary.json"
        evidence.parent.mkdir(parents=True, exist_ok=True)
        evidence.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print("\n=== summary ===")
        print(f"session:  {summary['session_id']}")
        print(f"lab:      {summary['lab_dir']}")
        print(f"database: {summary['database']}")
        print(f"status:   {os.environ.get(ENV_STATUS)}")
        print("Investigate Terminal 1: p i e n s a r t")
        print("Cleanup when done: ./scripts/cleanup-lab.sh")
    return 0


def main(argv: list[str] | None = None) -> int:
    return run_lab(parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
