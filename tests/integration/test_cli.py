import json
import subprocess
import sys
from pathlib import Path

import pytest

from runtime_engine.main import main


def test_full_pipeline_and_commands(tmp_path, capsys):
    db = tmp_path / "test.db"
    prefix = ["--db", str(db)]
    assert main(prefix + ["replay", "--input", "datasets/chain.jsonl"]) == 0
    metrics = json.loads(capsys.readouterr().out)
    assert metrics["total_events_processed"] == 6
    assert metrics["total_incidents_created"] == 1
    assert metrics["average_processing_latency_ms"] > 0
    for command in [["incidents"], ["incident", "--id", "INC-0001"], ["metrics"], ["rules"]]:
        assert main(prefix + command) == 0
        output_text = capsys.readouterr().out
        if command[0] == "incident":
            assert "TIMELINE:" in output_text and "INCIDENT: INC-0001" in output_text
        else:
            assert json.loads(output_text)
    output = tmp_path / "report.json"
    assert (
        main(prefix + ["export", "--id", "INC-0001", "--format", "json", "--output", str(output)])
        == 0
    )
    assert json.loads(output.read_text())["event_count"] == 5
    assert main(prefix + ["export", "--id", "INC-0001", "--output", str(output)]) == 1
    assert main(prefix + ["incident", "--id", "absent"]) == 3


def test_invalid_cli_inputs(tmp_path, capsys):
    prefix = ["--db", str(tmp_path / "test.db")]
    assert main(prefix + ["replay", "--input", "missing.jsonl"]) == 1
    bad = tmp_path / "bad.jsonl"
    bad.write_text("bad\n")
    assert main(prefix + ["replay", "--input", str(bad)]) == 2
    config = tmp_path / "config.yaml"
    config.write_text("poll_interval_seconds: -1")
    assert main(["--config", str(config), "rules"]) == 1
    with pytest.raises(SystemExit) as exc:
        main(["unknown"])
    assert exc.value.code == 2


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux /proc only")
def test_live_proc_monitor_read_only(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "runtime_engine.main",
            "--db",
            str(tmp_path / "live.db"),
            "monitor",
            "--duration",
            "0.1",
            "--json",
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["total_events_processed"] > 0


def test_installed_entry_and_import():
    result = subprocess.run(
        [sys.executable, "-m", "runtime_engine.main", "--help"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert "Read-only" in result.stdout


def test_yaml_rules_are_packaged():
    from importlib.resources import files

    assert files("runtime_engine.data").joinpath("default_rules.yaml").is_file()


def test_malformed_yaml_returns_meaningful_exit(tmp_path):
    config = tmp_path / "bad.yaml"
    config.write_text("[bad: [")
    assert main(["--config", str(config), "rules"]) == 1


def test_report_context_is_original_observed_evidence(database):
    from runtime_engine.collector.replay_collector import ReplayCollector
    from runtime_engine.detection.rule_loader import load_rules
    from runtime_engine.incidents.generator import generate
    from runtime_engine.pipeline import Pipeline

    pipeline = Pipeline(database, load_rules())
    for event in ReplayCollector(Path("datasets/chain.jsonl")).collect():
        pipeline.process(event)
    report = generate(database, "INC-0001")
    assert report["context_events"][0]["process_name"] == "soffice"
    assert report["context_events"][0]["event_id"] == "synthetic-chain-1"
    assert len(report["related_processes"]) == 3
