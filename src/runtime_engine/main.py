"""Command-line entry point. No monitored command is ever executed."""

import argparse
import json
import logging
import sqlite3
import sys
from collections.abc import Sequence
from pathlib import Path

import yaml
from pydantic import ValidationError

from runtime_engine.config.settings import Settings
from runtime_engine.detection.rule_loader import load_rules
from runtime_engine.incidents.generator import generate
from runtime_engine.incidents.reporter import export_json, terminal
from runtime_engine.monitor.state import Verbosity
from runtime_engine.storage.database import Database
from runtime_engine.terminal import app

MONITOR_EPILOG = """\
interactive commands (dashboard mode):
  h help   p inspect process   i inspect incident   e inspect events
  m metrics   r recent alerts   q stop   Ctrl+C graceful stop (twice forces)

The dashboard needs an interactive terminal on stdin and stdout. Otherwise, or with
--no-dashboard, events are printed as log lines. A session report is printed on stop
and the session is saved; list saved sessions with the `sessions` command.
"""
NOT_FOUND = {
    "process": "error: no stored process with that PID",
    "session": "error: session not found",
}


def positive(value: str) -> float:
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Read-only Linux runtime threat detection prototype"
    )
    result.add_argument("--config", type=Path, help="YAML settings file")
    result.add_argument("--db", type=Path, help="SQLite path (default: runtime.db)")
    result.add_argument("--rules", type=Path, help="Custom YAML rules (default: bundled)")
    result.add_argument("--verbose", action="store_true", help="Show collector diagnostics")
    sub = result.add_subparsers(dest="command", required=True)
    replay = sub.add_parser("replay", help="Replay synthetic or authorized JSONL telemetry")
    replay.add_argument("--input", required=True, type=Path)
    replay.add_argument("--sort", action="store_true", help="Buffer and sort by event timestamp")
    replay.add_argument(
        "--summary", action="store_true", help="Print the session report instead of JSON metrics"
    )
    monitor = sub.add_parser(
        "monitor",
        help="Live /proc monitoring dashboard (read-only); q or Ctrl-C stops cleanly",
        epilog=MONITOR_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    monitor.add_argument("--duration", type=float, help="Stop after this many seconds")
    monitor.add_argument(
        "--include-cmdline", action="store_true", help="Opt in to sensitive argv storage"
    )
    monitor.add_argument(
        "--verbosity",
        choices=[v.name.lower() for v in Verbosity],
        default="normal",
        help="quiet: findings and errors; normal (default): plus new processes; "
        "verbose: plus baseline and repeats; debug: plus internal diagnostics",
    )
    monitor.add_argument(
        "--refresh", type=positive, help="Dashboard refresh interval in seconds (default: 1.0)"
    )
    monitor.add_argument(
        "--no-dashboard", action="store_true", help="Print log lines instead of the dashboard"
    )
    monitor.add_argument(
        "--json",
        action="store_true",
        help="Print only the JSON metrics to stdout at the end (log lines go to stderr)",
    )
    monitor.add_argument(
        "--queue-capacity", type=int, help="Bounded collector-to-pipeline queue size"
    )
    sub.add_parser("incidents", help="List persisted incidents")
    show = sub.add_parser("incident", help="Show one incident with evidence")
    show.add_argument("--id", required=True)
    export = sub.add_parser("export", help="Export one incident as JSON to stdout or file")
    export.add_argument("--id", required=True)
    export.add_argument("--format", choices=["json"], default="json")
    export.add_argument("--output", type=Path)
    sub.add_parser("metrics", help="Show actual counters for each completed session")
    sub.add_parser("rules", help="List enabled bundled or custom detection rules")
    process = sub.add_parser("process", help="Inspect a stored process: rules, events, ancestry")
    process.add_argument("--pid", required=True, type=int)
    process.add_argument("--json", action="store_true")
    events = sub.add_parser("events", help="List recently stored events with filters")
    events.add_argument("--limit", type=int, default=50)
    events.add_argument("--pid", type=int)
    events.add_argument("--type", help="Event type, e.g. PROCESS_START")
    events.add_argument("--name", help="Exact process name")
    events.add_argument(
        "--filter",
        default="",
        help="Extra terms, e.g. 'severity=HIGH since=10m kind=match incident=INC-0001'",
    )
    events.add_argument("--json", action="store_true")
    sessions = sub.add_parser("sessions", help="List recorded monitoring and replay sessions")
    sessions.add_argument("--json", action="store_true")
    session = sub.add_parser("session", help="Show one recorded session report")
    session.add_argument("--id", required=True)
    session.add_argument("--json", action="store_true")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s %(message)s",
    )
    database: Database | None = None
    console = app.cli_console()
    try:
        settings = Settings.load(args.config)
        rules = load_rules(args.rules)
        if args.command == "rules":
            print(json.dumps([r.model_dump(mode="json") for r in rules if r.enabled], indent=2))
            return 0
        if args.command == "monitor":
            if not sys.platform.startswith("linux"):
                raise ValueError("monitor requires Linux /proc")
            if args.duration is not None and args.duration <= 0:
                raise ValueError("duration must be positive")
            if args.queue_capacity is not None and args.queue_capacity < 1:
                raise ValueError("queue capacity must be positive")
        database = Database(args.db or settings.database)
        if args.command == "replay":
            return app.run_replay(
                database, rules, settings, args.input, sort=args.sort, summary_output=args.summary
            )
        if args.command == "monitor":
            verbosity = Verbosity.parse(args.verbosity)
            if args.verbose and verbosity < Verbosity.DEBUG:
                logging.getLogger("runtime_engine").setLevel(logging.DEBUG)
            options = app.MonitorOptions(
                duration=args.duration,
                include_cmdline=args.include_cmdline or settings.include_cmdline,
                verbosity=verbosity,
                refresh=args.refresh or settings.dashboard_refresh_seconds,
                dashboard=False if args.no_dashboard else None,
                json_output=args.json,
                queue_capacity=args.queue_capacity or settings.event_queue_capacity,
            )
            return app.run_monitor(database, rules, settings, options)
        if args.command == "incidents":
            print(
                json.dumps(
                    [
                        i.model_dump(mode="json") | {"event_count": i.event_count}
                        for i in database.incidents()
                    ],
                    indent=2,
                )
            )
        elif args.command == "metrics":
            print(json.dumps({"sessions": database.metrics()}, indent=2))
        elif args.command == "sessions":
            return app.show_sessions(database, console, args.json)
        elif args.command == "session":
            return app.show_session(database, console, args.id, args.json)
        elif args.command == "process":
            return app.show_process(database, console, args.pid, args.json)
        elif args.command == "events":
            return app.show_events(
                database,
                console,
                limit=args.limit,
                pid=args.pid,
                event_type=args.type,
                name=args.name,
                filter_text=args.filter,
                as_json=args.json,
            )
        else:
            report = generate(database, args.id)
            if args.command == "export":
                text = export_json(report)
                if args.output:
                    # Fail instead of overwriting an existing report or an arbitrary file.
                    with args.output.open("x", encoding="utf-8") as stream:
                        stream.write(text)
                else:
                    print(text, end="")
            else:
                print(terminal(report))
        return 0
    except KeyError:
        print(NOT_FOUND.get(args.command, "error: incident not found"), file=sys.stderr)
        return 3
    except (OSError, ValueError, ValidationError, sqlite3.Error, yaml.YAMLError) as exc:
        print(
            f"error: {type(exc).__name__}; use --help and check paths/configuration",
            file=sys.stderr,
        )
        return 1
    finally:
        if database:
            database.close()


if __name__ == "__main__":
    raise SystemExit(main())
