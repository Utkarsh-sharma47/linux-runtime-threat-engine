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
from runtime_engine.terminal import app, atomic_app, security_app

MONITOR_EPILOG = """\
interactive commands (dashboard mode):
  h help   p inspect process   i inspect incident   e inspect events
  m metrics   r recent alerts   l live log   t process tree
  s security modules   n network investigation   a Atomic sessions
  q stop   Ctrl+C graceful stop (twice forces)

The dashboard needs an interactive terminal on stdin and stdout. Otherwise, or with
--no-dashboard, events are printed as log lines. A session report is printed on stop
and the session is saved; list saved sessions with the `sessions` command.
"""
NOT_FOUND = {
    "persistence": "error: finding not found",
    "network": "error: finding not found",
    "anomaly": "error: no live process with that PID",
    "integrity": "error: file not in the integrity tree",
    "exposure": "error: finding not found",
    "process": "error: no stored process with that PID",
    "session": "error: session not found",
    "atomic": "error: Atomic run not found (see: atomic runs)",
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
    monitor.add_argument(
        "--no-security-modules",
        action="store_true",
        help="Do not run the scheduled security modules (persistence, ...)",
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
    persistence = sub.add_parser(
        "persistence",
        help="Persistence and privilege monitoring: baseline, scan, show",
        description="Read-only comparison of systemd units, cron, SSH authorized_keys, "
        "sudoers, SUID/SGID executables, file capabilities and sensitive executable "
        "directories against a stored baseline.",
    )
    persistence.add_argument("action", choices=["baseline", "scan", "show"])
    persistence.add_argument("--id", dest="finding_id", help="Show one finding (with show)")
    persistence.add_argument("--json", action="store_true")
    network = sub.add_parser(
        "network",
        help="Network connections by process, beacon analysis and findings",
        description="connections: current sockets with process attribution; process: one "
        "PID's sockets and stored connection events; analyze: periodicity of a JSONL "
        "timeline (--input) or synthetic timelines (--demo); show: stored findings.",
    )
    network.add_argument("action", choices=["connections", "process", "analyze", "show"])
    network.add_argument("--pid", type=int)
    network.add_argument("--input", type=Path, help="JSONL with time, destination, process")
    network.add_argument("--demo", action="store_true", help="Analyze synthetic timelines")
    network.add_argument("--id", dest="finding_id", help="Show one finding (with show)")
    network.add_argument("--json", action="store_true")
    anomaly = sub.add_parser(
        "anomaly",
        help="Process anomaly detection: train, status, score, inspect, collect, demo",
        description="Isolation Forest (scikit-learn, optional '.[ml]' extra) or a deterministic "
        "robust z-score fallback. train: fit a reviewed baseline dataset; score: rank a "
        "dataset; inspect: score live processes now; collect: write host rows for review; "
        "demo: synthetic baseline and injected outliers. Scores are not malware probabilities.",
    )
    anomaly.add_argument(
        "action", choices=["train", "status", "score", "inspect", "collect", "demo"]
    )
    anomaly.add_argument("--dataset", type=Path, help="JSONL rows with a 'features' object")
    anomaly.add_argument("--algorithm", choices=["auto", "iforest", "robust"])
    anomaly.add_argument(
        "--i-reviewed-baseline",
        dest="reviewed",
        action="store_true",
        help="Confirm a host-collected dataset was reviewed before training",
    )
    anomaly.add_argument("--model-dir", type=Path)
    anomaly.add_argument("--pid", type=int)
    anomaly.add_argument("--top", type=int, default=15)
    anomaly.add_argument("--duration", type=positive, default=60)
    anomaly.add_argument("--interval", type=positive, default=10)
    anomaly.add_argument("--output", type=Path)
    anomaly.add_argument("--json", action="store_true")
    integrity = sub.add_parser(
        "integrity",
        help="SHA-256 Merkle-tree file integrity: baseline, verify, show, proof, keygen, demo",
        description="baseline: hash configured files into a Merkle tree (optionally export a "
        "root anchor, HMAC-signed with --key-file); verify: recompute and list added, deleted "
        "and modified files (--anchor checks the stored baseline against an exported root); "
        "proof: membership proof for one file; demo: temporary files only.",
    )
    integrity.add_argument(
        "action", choices=["baseline", "verify", "show", "proof", "keygen", "demo"]
    )
    integrity.add_argument(
        "--path", dest="paths", action="append", help="File or directory (repeatable)"
    )
    integrity.add_argument("--export", type=Path, help="Write the root anchor manifest (new file)")
    integrity.add_argument("--key-file", type=Path, help="HMAC key for signing or checking anchors")
    integrity.add_argument("--anchor", type=Path, help="Exported anchor manifest to verify against")
    integrity.add_argument("--full", action="store_true", help="Re-hash every file")
    integrity.add_argument("--file", help="File for proof")
    integrity.add_argument(
        "--baseline",
        dest="use_baseline",
        action="store_true",
        help="Prove membership in the baseline tree instead of the current one",
    )
    integrity.add_argument("--output", type=Path, help="Key file to create (keygen)")
    integrity.add_argument("--keep", action="store_true", help="Keep the demo directory")
    integrity.add_argument("--json", action="store_true")
    exposure = sub.add_parser(
        "exposure",
        help="Attack surface analysis: scan, report, baseline, show",
        description="Read-only posture checks: SUID/SGID, capabilities, writable PATH dirs, "
        "sensitive file permissions, root listening services, root units, suspicious process "
        "locations and sudoers patterns (when readable). baseline accepts current findings "
        "as known posture. Nothing on the host is modified.",
    )
    exposure.add_argument("action", choices=["scan", "report", "baseline", "show"])
    exposure.add_argument(
        "--incremental", action="store_true", help="Reuse the saved scan state (scan only)"
    )
    exposure.add_argument("--severity", choices=["low", "medium", "high", "critical"])
    exposure.add_argument("--rule", help="Only one rule, e.g. EX001")
    exposure.add_argument("--id", dest="finding_id", help="Finding to show")
    exposure.add_argument("--json", action="store_true")
    ransomware = sub.add_parser(
        "ransomware",
        help="Ransomware early warning: demo, simulate, watch, report, cleanup",
        description="Behavioural detection (modification and rename rates, affected files, "
        "entropy rises, extension changes) on explicitly chosen directories. demo and "
        "simulate only touch files they create in a dedicated lab under the system temp "
        "directory; no real encryption or user data is involved.",
    )
    ransomware.add_argument("action", choices=["demo", "simulate", "watch", "report", "cleanup"])
    ransomware.add_argument("--lab-dir", help="Lab directory (must be <tmp>/rte-ransomware-lab*)")
    ransomware.add_argument("--dir", dest="directory", help="Directory to watch (watch)")
    ransomware.add_argument("--files", type=int, default=30)
    ransomware.add_argument("--delay", type=float, default=0.03)
    ransomware.add_argument("--duration", type=positive, default=30)
    ransomware.add_argument("--keep", action="store_true", help="Keep the demo lab files")
    ransomware.add_argument("--json", action="store_true")
    atomic_app.add_parser(sub)
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
        if args.command == "atomic":
            atomic_app.validate(args)
            return atomic_app.command(args, settings, rules, console)
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
                security_modules=not args.no_security_modules,
            )
            return app.run_monitor(database, rules, settings, options)
        if args.command == "persistence":
            return security_app.persistence_command(
                database,
                settings,
                rules,
                console,
                args.action,
                as_json=args.json,
                finding_id=args.finding_id,
            )
        if args.command == "network":
            return security_app.network_command(
                database,
                settings,
                console,
                args.action,
                as_json=args.json,
                pid=args.pid,
                finding_id=args.finding_id,
                input_path=args.input,
                demo=args.demo,
            )
        if args.command == "anomaly":
            return security_app.anomaly_command(
                database,
                settings,
                console,
                args.action,
                as_json=args.json,
                dataset=args.dataset,
                algorithm=args.algorithm,
                reviewed=args.reviewed,
                model_dir=args.model_dir,
                pid=args.pid,
                top=args.top,
                duration=args.duration,
                interval=args.interval,
                output=args.output,
            )
        if args.command == "integrity":
            return security_app.integrity_command(
                database,
                settings,
                rules,
                console,
                args.action,
                as_json=args.json,
                paths=args.paths,
                export=args.export,
                key_file=args.key_file,
                anchor=args.anchor,
                full=args.full,
                file=args.file,
                use_baseline=args.use_baseline,
                output=args.output,
                keep=args.keep,
            )
        if args.command == "exposure":
            return security_app.exposure_command(
                database,
                settings,
                rules,
                console,
                args.action,
                as_json=args.json,
                incremental=args.incremental,
                severity=args.severity,
                rule=args.rule,
                finding_id=args.finding_id,
            )
        if args.command == "ransomware":
            return security_app.ransomware_command(
                database,
                settings,
                rules,
                console,
                args.action,
                as_json=args.json,
                lab_dir=args.lab_dir,
                directory=args.directory,
                files=args.files,
                delay=args.delay,
                duration=args.duration,
                keep=args.keep,
            )
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
