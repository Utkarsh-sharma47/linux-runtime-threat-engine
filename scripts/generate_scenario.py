#!/usr/bin/env python3
"""Generate inert synthetic JSONL records. Never run a scenario's command strings."""

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

BASE = datetime(2026, 1, 1, tzinfo=UTC)


def event(scenario: str, number: int, **fields: object) -> dict[str, object]:
    return {
        "event_id": f"synthetic-{scenario}-{number}",
        "timestamp": (BASE + timedelta(seconds=number)).isoformat(),
        "event_type": "PROCESS_START",
        "pid": 100,
        "process_start_time": "1000",
        "host_id": f"synthetic-{scenario}",
        "source": "synthetic",
        "metadata": {"synthetic": True, "scenario": scenario},
        **fields,
    }


def scenarios() -> dict[str, list[dict[str, object]]]:
    benign = [
        event(
            "benign",
            1,
            process_name="bash",
            parent_process_name="terminal",
            executable_path="/usr/bin/bash",
        ),
        event(
            "benign",
            2,
            pid=101,
            process_start_time="1010",
            process_name="python3",
            parent_process_name="systemd",
            executable_path="/usr/bin/python3",
        ),
    ]
    shell = [event("shell", 1, process_name="bash", parent_process_name="soffice")]
    chain = [
        event("chain", 1, process_name="soffice"),
        event(
            "chain",
            2,
            pid=110,
            process_start_time="1100",
            ppid=100,
            parent_start_time="1000",
            process_name="bash",
        ),
        event(
            "chain",
            3,
            event_type="FILE_ACCESS",
            pid=110,
            process_start_time="1100",
            process_name="bash",
            file_path="/etc/shadow",
        ),
        event(
            "chain",
            4,
            pid=120,
            process_start_time="1200",
            ppid=110,
            parent_start_time="1100",
            process_name="curl",
            executable_path="/tmp/curl",
        ),
        event(
            "chain",
            5,
            event_type="NETWORK_CONNECTION",
            pid=120,
            process_start_time="1200",
            network_destination="203.0.113.10",
        ),
        event(
            "chain",
            6,
            event_type="PRIVILEGE_CHANGE",
            pid=110,
            process_start_time="1100",
            previous_uid=1000,
            uid=0,
        ),
    ]
    sensitive = [event("sensitive", 1, event_type="FILE_ACCESS", file_path="/etc/shadow")]
    repeated = [
        event("repeated", n, event_type="FILE_ACCESS", file_path="/etc/shadow") for n in range(1, 4)
    ]
    repeated.append(dict(repeated[0]))  # Same event ID: do not store the record twice.
    unrelated = [
        event("unrelated", 1, event_type="FILE_ACCESS", file_path="/etc/shadow"),
        event(
            "unrelated",
            2,
            pid=500,
            process_start_time="5000",
            event_type="FILE_ACCESS",
            file_path="/etc/shadow",
        ),
    ]
    return dict(
        benign=benign,
        shell=shell,
        chain=chain,
        sensitive=sensitive,
        repeated=repeated,
        unrelated=unrelated,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("datasets"))
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    data = scenarios()
    for name, events in data.items():
        (args.output_dir / f"{name}.jsonl").write_text(
            "".join(json.dumps(e, sort_keys=True) + "\n" for e in events)
        )
    (args.output_dir / "sample_events.jsonl").write_text(
        "".join(json.dumps(e, sort_keys=True) + "\n" for events in data.values() for e in events)
    )


if __name__ == "__main__":
    main()
