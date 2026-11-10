#!/usr/bin/env python3
"""Measure an actual synthetic JSONL replay and SQLite persistence on this machine."""

import argparse
import importlib.metadata
import json
import os
import platform
import sqlite3
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter

from runtime_engine.collector.replay_collector import ReplayCollector
from runtime_engine.detection.rule_loader import load_rules
from runtime_engine.pipeline import Pipeline
from runtime_engine.storage.database import Database


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=2000)
    args = parser.parse_args()
    if args.events <= 0:
        parser.error("--events must be positive")
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        dataset = root / "benchmark.jsonl"
        base = datetime(2026, 1, 1, tzinfo=UTC)
        with dataset.open("w") as stream:
            for number in range(args.events):
                raw = dict(
                    event_id=f"benchmark-{number}",
                    timestamp=(base + timedelta(milliseconds=number)).isoformat(),
                    event_type="FILE_ACCESS" if number % 20 == 0 else "PROCESS_START",
                    pid=1000 + number,
                    process_start_time=str(1000 + number),
                    process_name="synthetic-tool",
                    host_id="synthetic-benchmark",
                    source="synthetic",
                    metadata={"synthetic": True},
                )
                if number % 20 == 0:
                    raw["file_path"] = "/etc/shadow"
                stream.write(json.dumps(raw) + "\n")
        db_path = root / "benchmark.db"
        database = Database(db_path)
        pipeline = Pipeline(database, load_rules())
        collector = ReplayCollector(dataset)
        started = perf_counter()
        for event in collector.collect():
            pipeline.process(event)
        seconds = perf_counter() - started
        report = {
            "environment": {
                "python": platform.python_version(),
                "system": platform.system(),
                "kernel": platform.release(),
                "architecture": platform.machine(),
                "logical_cpus": os.cpu_count(),
                "sqlite": sqlite3.sqlite_version,
                "pydantic": importlib.metadata.version("pydantic"),
            },
            "dataset": {"synthetic": True, "records": args.events, "alerting_fraction": 0.05},
            "replay_wall_seconds": seconds,
            "replay_wall_events_per_second": args.events / seconds,
            "sqlite_bytes": db_path.stat().st_size,
            "metrics": pipeline.metrics.report(),
            "caveat": "Single local run, not a production capacity or detection accuracy claim. "
            "Wall time includes JSONL parsing; pipeline latency excludes collector work.",
        }
        database.close()
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
