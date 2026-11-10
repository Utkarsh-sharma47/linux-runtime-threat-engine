"""Command-line entry point. No monitored command is ever executed."""

import argparse
import json
import logging
import sqlite3
import sys
import time
from collections.abc import Sequence
from pathlib import Path

import yaml
from pydantic import ValidationError

from runtime_engine.collector.proc_collector import ProcCollector
from runtime_engine.collector.replay_collector import ReplayCollector
from runtime_engine.config.settings import Settings
from runtime_engine.detection.rule_loader import load_rules
from runtime_engine.incidents.generator import generate
from runtime_engine.incidents.reporter import export_json, terminal
from runtime_engine.pipeline import Pipeline
from runtime_engine.storage.database import Database


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
    monitor = sub.add_parser("monitor", help="Poll /proc read-only; Ctrl-C stops cleanly")
    monitor.add_argument("--duration", type=float, help="Stop after this many seconds")
    monitor.add_argument(
        "--include-cmdline", action="store_true", help="Opt in to sensitive argv storage"
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
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s %(message)s",
    )
    database: Database | None = None
    try:
        settings = Settings.load(args.config)
        rules = load_rules(args.rules)
        if args.command == "rules":
            print(json.dumps([r.model_dump(mode="json") for r in rules if r.enabled], indent=2))
            return 0
        database = Database(args.db or settings.database)
        if args.command in ("replay", "monitor"):
            pipeline = Pipeline(database, rules, settings.correlation_window_seconds)
            collector: ReplayCollector | ProcCollector
            if args.command == "replay":
                collector = ReplayCollector(args.input, sort=args.sort)
                for event in collector.collect():
                    pipeline.process(event)
            else:
                if not sys.platform.startswith("linux"):
                    raise ValueError("monitor requires Linux /proc")
                if args.duration is not None and args.duration <= 0:
                    raise ValueError("duration must be positive")
                collector = ProcCollector(
                    include_cmdline=args.include_cmdline or settings.include_cmdline
                )
                deadline = time.monotonic() + args.duration if args.duration else None
                try:
                    while True:
                        for event in collector.collect():
                            pipeline.process(event)
                        if deadline is not None and time.monotonic() >= deadline:
                            break
                        delay = settings.poll_interval_seconds
                        if deadline is not None:
                            delay = min(delay, max(0, deadline - time.monotonic()))
                        time.sleep(delay)
                except KeyboardInterrupt:
                    logging.info("monitor_stopped reason=keyboard_interrupt")
            pipeline.metrics.events_rejected += collector.rejected
            pipeline.metrics.collector_errors += collector.errors
            report = pipeline.metrics.report()
            database.save_metrics(report)
            print(json.dumps(report, indent=2))
            return 2 if pipeline.metrics.events_rejected else 0
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
        print("error: incident not found", file=sys.stderr)
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
