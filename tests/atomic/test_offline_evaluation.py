"""Offline Atomic evaluation workflow, with synthetic atomics, traces and launchers.

No Atomic test and no Invoke-AtomicTest is executed: launchers are small shell
commands in temporary directories. Tracing tests run real strace on those commands and
are skipped when strace is unavailable.
"""

import json
import os
import shlex
import shutil
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from runtime_engine.atomic import analysis, catalog, preflight, profiles, runner, trace
from runtime_engine.atomic.analysis import (
    DETECTED,
    EXECUTION_FAILED,
    INCONCLUSIVE,
    NOT_APPLICABLE,
    NOT_DETECTED,
    PARTIAL,
    Component,
    grade_component,
    overall,
)
from runtime_engine.atomic.profiles import ModuleExpectation, Profile
from runtime_engine.config.settings import Settings
from runtime_engine.detection.rule_loader import load_rules
from runtime_engine.events.schema import Event
from runtime_engine.main import main
from runtime_engine.pipeline import Pipeline
from runtime_engine.storage.database import Database
from runtime_engine.terminal.views import atomic_view

STRACE = preflight.environment(Path("/nonexistent"), probe_module=False).tracing
needs_strace = pytest.mark.skipif(not STRACE, reason="strace tracing not available here")

ATOMIC_YAML = {
    "attack_technique": "T1059.004",
    "display_name": "Command and Scripting Interpreter: Unix Shell",
    "atomic_tests": [
        {
            "name": "windows only",
            "auto_generated_guid": "00000000-0000-0000-0000-000000000001",
            "supported_platforms": ["windows"],
            "executor": {"name": "powershell", "command": "Get-Date"},
        },
        {
            "name": "write a lab file",
            "auto_generated_guid": "11111111-2222-3333-4444-555555555555",
            "description": "writes #{target}",
            "supported_platforms": ["linux"],
            "input_arguments": {"target": {"type": "path", "default": "/tmp/x.txt"}},
            "executor": {
                "name": "sh",
                "command": "echo atomic > #{target}",
                "cleanup_command": "rm #{target}",
            },
        },
        {
            "name": "needs root",
            "auto_generated_guid": "22222222-2222-3333-4444-555555555555",
            "supported_platforms": ["linux"],
            "executor": {"name": "sh", "command": "id", "elevation_required": True},
        },
        {
            "name": "has prerequisites",
            "auto_generated_guid": "33333333-2222-3333-4444-555555555555",
            "supported_platforms": ["linux"],
            "dependencies": [
                {"description": "tool", "prereq_command": "which x", "get_prereq_command": "x"}
            ],
            "executor": {"name": "sh", "command": "uname -a"},
        },
        {
            "name": "persistence",
            "auto_generated_guid": "44444444-2222-3333-4444-555555555555",
            "supported_platforms": ["linux"],
            "executor": {"name": "sh", "command": "crontab /tmp/evil"},
        },
        {
            "name": "read only",
            "auto_generated_guid": "55555555-2222-3333-4444-555555555555",
            "supported_platforms": ["linux"],
            "input_arguments": {"src": {"type": "path", "default": "PathToAtomicsFolder/x"}},
            "executor": {"name": "sh", "command": "uname -srm; ls #{src}"},
        },
    ],
}


@pytest.fixture
def atomics(tmp_path: Path) -> Path:
    folder = tmp_path / "atomics" / "T1059.004"
    folder.mkdir(parents=True)
    (folder / "T1059.004.yaml").write_text(yaml.safe_dump(ATOMIC_YAML))
    return tmp_path / "atomics"


def env(atomics: Path, **changes: Any) -> preflight.Environment:
    base = preflight.Environment(
        atomics=str(atomics),
        atomics_present=True,
        atomics_commit="test",
        pwsh="/usr/bin/false",
        module_version="2.3.0",
        strace=shutil.which("strace"),
        ptrace_scope=1 if STRACE else None,
        virtualization="none",
        uid=1000 if os.getuid() == 0 else os.getuid(),
    )
    return replace(base, **changes)


def profile(**values: Any) -> Profile:
    data: dict[str, Any] = {"technique": "T1059.004", "name": "write a lab file"}
    data.update(values)
    return Profile.model_validate(data)


# ----- catalog, profiles and preflight -----


def test_catalog_metadata_numbering_and_rendering(atomics: Path) -> None:
    test = catalog.find_test(atomics, "t1059.004", 2)
    assert test is not None and test.name == "write a lab file"
    assert test.number == 2  # numbering counts the Windows-only test too
    assert catalog.find_test(atomics, "T1059.004", 1) is None  # not a Linux test
    assert catalog.find_test(atomics, "T1003", 1) is None
    with pytest.raises(ValueError):
        catalog.find_test(atomics, "../etc", 1)
    assert catalog.render(test.command, test.input_arguments) == "echo atomic > /tmp/x.txt"
    assert (
        catalog.render(test.command, test.input_arguments, {"target": "/tmp/lab/y"})
        == "echo atomic > /tmp/lab/y"
    )
    readonly = catalog.find_test(atomics, "T1059.004", 6)
    assert readonly is not None
    assert catalog.render("ls PathToAtomicsFolder/x", {}, None, atomics) == f"ls {atomics}/x"


def test_profiles_reviewed_risk_fixtures_and_overrides(tmp_path: Path) -> None:
    item = profile(reviewed_risk="B", input_args={"target": "/tmp/lab"})
    assert item.risk_for({"target": "/tmp/lab"}) == "B"
    assert item.risk_for({}) is None and item.risk_for({"target": "/etc/x"}) is None
    assert item.expectations() == {"rules": ModuleExpectation(rules=[])}
    with pytest.raises(ValueError):
        profile(fixtures={"/etc/passwd": "x"})
    with pytest.raises(ValueError):
        profile(fixtures={"/tmp/rte-atomic-lab/../etc/x": "x"})
    with pytest.raises(ValueError):
        profile(module_paths={"exposure.weights": ["x"]})
    with pytest.raises(ValueError):
        profile(modules={"magic": {"rules": []}})
    assert profiles.parse_overrides(["a=1", "b=x=y"]) == {"a": "1", "b": "x=y"}
    with pytest.raises(ValueError):
        profiles.parse_overrides(["no-equals"])
    path = tmp_path / "p.yaml"
    path.write_text("ABC-guid:\n  technique: T1\n  name: n\n")
    assert list(profiles.load_profiles(path)) == ["abc-guid"]
    assert profiles.load_profiles(tmp_path / "missing.yaml") == {}
    real = profiles.load_profiles(Path("testing/atomic-red-team/expectations.yaml"))
    assert real["b04ed73c-7d43-4dc8-b563-a2fc595cba1a"].benign


def test_preflight_refusals_and_approvals(atomics: Path, tmp_path: Path) -> None:
    guid = "11111111-2222-3333-4444-555555555555"
    profs = {guid: profile()}
    base = env(atomics)
    pre = preflight.check(base, "T1059.004", 2, profs)
    assert any("risk class B" in r for r in pre.refusals) and pre.token == "11111111"
    assert pre.cleanup == "rm /tmp/x.txt"
    assert not preflight.check(base, "T1059.004", 2, profs, allow_review_required=True).refusals
    assert "requires root" in " ".join(preflight.check(base, "T1059.004", 3, {}).refusals)
    assert "prerequisites" in " ".join(preflight.check(base, "T1059.004", 4, {}).refusals)
    reviewed = preflight.check(base, "T1059.004", 4, {}, prereqs_reviewed=True)
    assert not any("prerequisites" in r for r in reviewed.refusals)
    risky = preflight.check(base, "T1059.004", 5, {}, isolated_vm=True)
    assert any("class C" in r for r in risky.refusals)  # not inside a VM
    vm = env(atomics, virtualization="kvm")
    assert not any("class C" in r for r in preflight.check(vm, "T1059.004", 5, {},
                                                         isolated_vm=True).refusals)  # fmt: skip
    unknown = preflight.check(base, "T1059.004", 2, profs, {"nope": "1"})
    assert any("unknown input arguments" in r for r in unknown.refusals)
    root = preflight.check(env(atomics, uid=0), "T1059.004", 6, {})
    assert any("root" in r for r in root.refusals)
    missing = preflight.check(env(atomics, module_version=None), "T1059.004", 6, {})
    assert any("not installed" in r for r in missing.refusals)
    clean = preflight.check(base, "T1059.004", 6, {})
    assert clean.risk == "A" and not clean.refusals
    assert any("no reviewed expectation profile" in w for w in clean.warnings)
    gone = preflight.check(env(atomics, atomics_present=False), "T1059.004", 6, {})
    assert gone.test is None and gone.refusals
    helper = tmp_path / "helper"
    helper.write_text("#!/bin/sh\n")
    helper.chmod(0o4755)
    assert preflight.privileged_helpers(f"{helper} --x; echo hi") == [str(helper)]
    unsafe = preflight.check(
        base, "T1059.004", 2, {guid: profile(cleanup_safe=False, cleanup_note="bad")}
    )
    assert any("UNSAFE" in w for w in unsafe.warnings)
    data = clean.as_dict()
    assert data["test"]["number"] == 6 and data["approval_token"] == "55555555"


# ----- strace parsing -----

TRACE = (Path(__file__).parent / "data" / "strace-sample.txt").read_text()


def test_trace_parser_and_event_conversion() -> None:
    parsed = trace.parse(TRACE.splitlines())
    assert parsed.unparsed == 1 and parsed.first_pid == 100
    assert 101 not in parsed.processes  # a thread of pwsh, merged into its process
    assert parsed.processes[200].parent == 100  # vfork by the thread maps to the process
    conversion = trace.to_events(parsed, run_id="r1", root=200, uid=1000)
    events = conversion.events
    assert conversion.runner == 100 and conversion.root == 200
    assert all(e["pid"] != 300 for e in events)  # outside the executor's tree
    context = [e for e in events if e["metadata"].get("role")]
    assert [e["process_name"] for e in context] == ["pwsh"]
    starts = [e for e in events if e["event_type"] == "PROCESS_START" and e not in context]
    assert [e["process_name"] for e in starts] == ["sh", "mv", "crond"]
    sh = starts[0]
    assert sh["command_line"][2] == 'echo "hi"\nnexté'
    assert sh["metadata"]["command_line_truncated"] and sh["parent_process_name"] == "pwsh"
    crond = starts[2]
    assert crond["executable_path"] == "/tmp/lab/crond" and crond["ppid"] == 200
    assert crond["parent_start_time"] == sh["process_start_time"]
    files = {(e["file_path"], e["metadata"]["operation"]) for e in events
             if e["event_type"] == "FILE_ACCESS"}  # fmt: skip
    assert files == {
        ("/tmp/lab/out.txt", "open-write"),
        ("/etc/shadow", "open-read"),
        ("/tmp/lab/b", "rename"),
        ("/tmp/lab/b", "delete"),
        ("/tmp/lab/c", "chmod"),
    }
    shadow = next(e for e in events if e.get("file_path") == "/etc/shadow")
    assert shadow["metadata"]["result"] == "EACCES"
    rename = next(e for e in events if e["metadata"].get("operation") == "rename")
    assert rename["metadata"]["old_path"] == "/tmp/lab/a"
    chmod = next(e for e in events if e["metadata"].get("operation") == "chmod")
    assert chmod["metadata"]["mode"] == "04755"
    network = [e for e in events if e["event_type"] == "NETWORK_CONNECTION"]
    assert [(e["network_destination"], e["metadata"]["port"], e["metadata"]["result"])
            for e in network] == [("203.0.113.10", 443, "EINPROGRESS"),
                                  ("2001:db8::1", 80, "ok")]  # fmt: skip
    privilege = [e for e in events if e["event_type"] == "PRIVILEGE_CHANGE"]
    assert [(e["previous_uid"], e["uid"]) for e in privilege] == [(1000, 2000)]
    exits = {e["pid"]: e["metadata"]["exit"] for e in events if e["event_type"] == "PROCESS_EXIT"}
    assert exits == {201: "exit 0", 202: "killed by SIGKILL", 200: "exit 3"}
    stats = conversion.stats
    assert stats["failed_execs"] == 1 and stats["non_network_connects"] == 1
    assert stats["privilege_attempts"] == 2 and stats["file_reads_ignored"] == 1
    for event in events:  # every event is valid replay input
        Event.model_validate(event)
    unknown_root = trace.to_events(parsed, run_id="r1", root=999, uid=1000)
    assert unknown_root.root == 100  # falls back to the whole traced tree
    assert trace.to_events(trace.parse([]), run_id="r", root=None, uid=1).events == []


def test_strace_options_never_trace_payload_syscalls(tmp_path: Path) -> None:
    argv = trace.strace_argv(tmp_path / "t.txt", ["true"])
    traced = argv[argv.index("-e") + 1]
    for syscall in ("write", "sendto", "sendmsg", "recvfrom", "read"):
        assert f"?{syscall}," not in traced + "," and not traced.endswith(f"?{syscall}")
    assert "-v" not in argv  # environment blocks stay abbreviated
    assert argv[-2:] == ["--", "true"]


# ----- grading -----


def comp(grade: str, telemetry: bool = True) -> Component:
    return Component("x", "X", grade, [], [], [], telemetry, True)


def test_grading_rules_never_turn_missing_telemetry_into_not_detected() -> None:
    expect = ModuleExpectation(rules=["RT002"])
    gaps = ["no file telemetry"]
    assert (
        grade_component(expect, set(), telemetry=False, behaviour=True, gaps=gaps)[0]
        == INCONCLUSIVE
    )
    assert (
        grade_component(expect, {"RT002"}, telemetry=False, behaviour=True, gaps=gaps)[0]
        == INCONCLUSIVE
    )
    assert (
        grade_component(expect, {"RT002"}, telemetry=True, behaviour=True, gaps=[])[0] == DETECTED
    )
    assert (
        grade_component(expect, set(), telemetry=True, behaviour=True, gaps=[])[0] == NOT_DETECTED
    )
    assert (
        grade_component(expect, set(), telemetry=True, behaviour=False, gaps=[])[0] == INCONCLUSIVE
    )
    two = ModuleExpectation(rules=["RT005", "RT006"])
    assert grade_component(two, {"RT005"}, telemetry=True, behaviour=True, gaps=[])[0] == PARTIAL
    gap = grade_component(ModuleExpectation(), set(), telemetry=True, behaviour=True, gaps=[])
    assert gap[0] == NOT_DETECTED and "coverage gap" in gap[1][0]
    na = grade_component(None, {"RT001"}, telemetry=True, behaviour=True, gaps=[])
    assert na[0] == NOT_APPLICABLE and "unreviewed" in na[1][1]  # fmt: skip


def test_overall_outcomes_and_execution_success_is_not_detection() -> None:
    prof = profile()
    assert overall([comp(DETECTED)], "FAILED", prof)[0] == EXECUTION_FAILED
    assert overall([comp(DETECTED)], "TIMEOUT", prof)[0] == EXECUTION_FAILED
    assert overall([comp(DETECTED)], "COMPLETED", None)[0] == INCONCLUSIVE
    assert overall([comp(NOT_APPLICABLE)], "COMPLETED", prof)[0] == INCONCLUSIVE
    # Exit code 0 with the behaviour seen but nothing matched is a miss, not a success.
    assert overall([comp(NOT_DETECTED)], "COMPLETED", prof)[0] == NOT_DETECTED
    result, reasons = overall([comp(DETECTED), comp(INCONCLUSIVE, False)], "COMPLETED", prof)
    assert result == DETECTED and "not evaluated" in reasons[-1]
    assert overall([comp(DETECTED), comp(NOT_DETECTED)], "COMPLETED", prof)[0] == PARTIAL
    assert overall([comp(NOT_DETECTED), comp(INCONCLUSIVE)], "COMPLETED", prof)[0] == INCONCLUSIVE
    assert overall([comp(INCONCLUSIVE, False)], "COMPLETED", prof)[0] == INCONCLUSIVE


# ----- offline analysis of synthetic captured evidence -----


def synthetic_run(
    root: Path,
    *,
    guid: str,
    collector: str = "strace",
    status: str = "COMPLETED",
    events: list[dict[str, Any]] | None = None,
    run_id: str = "atomic-20260101T000000Z-T1036.003-2-a315bfff",
) -> Path:
    run = runner.private_dir(root / run_id)
    trace.write_jsonl(events or [], run / "events.jsonl")
    record = {
        "schema": runner.RECORD_SCHEMA,
        "run_id": run_id,
        "created_at": "2026-01-01T00:00:00+00:00",
        "test": {"technique": "T1036.003", "technique_name": "Masquerading", "number": 2,
                 "name": "masquerade", "guid": guid, "risk": "B", "risk_source": "test",
                 "overrides": {}, "command": "cp /bin/sh /tmp/crond", "cleanup": "rm /tmp/crond"},
        "execution": {"status": status, "exit_code": 0 if status == "COMPLETED" else 1,
                      "start_utc": "2026-01-01T00:00:00+00:00",
                      "end_utc": "2026-01-01T00:00:06+00:00", "duration_seconds": 6.0},
        "collection": {"collector": collector, "unavailable": ["synthetic"], "readability": {},
                       "integrity_paths": [], "ransomware_watch": []},
        "cleanup": {"status": "NOT RUN", "command": "rm /tmp/crond"},
    }  # fmt: skip
    (run / "record.json").write_text(json.dumps(record))
    return run


def ev(seq: int, kind: str, pid: int, **fields: Any) -> dict[str, Any]:
    base = {
        "event_id": f"syn:{seq}",
        "timestamp": (datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=seq)).isoformat(),
        "event_type": kind,
        "pid": pid,
        "uid": 1000,
        "process_start_time": f"t{pid}",
        "host_id": "atomic:test",
        "source": "atomic-strace",
        "metadata": {},
    }
    base.update(fields)
    return base


CROND_EVENTS = [
    ev(1, "PROCESS_START", 10, process_name="pwsh", executable_path="/usr/bin/pwsh",
       metadata={"role": "atomic-runner (context, not part of the test)"}),
    ev(2, "PROCESS_START", 20, process_name="sh", executable_path="/usr/bin/sh", ppid=10,
       parent_start_time="t10"),
    ev(3, "PROCESS_START", 30, process_name="crond", executable_path="/tmp/crond", ppid=20,
       parent_start_time="t20"),
    ev(4, "NETWORK_CONNECTION", 30, process_name="crond", network_destination="203.0.113.10",
       metadata={"port": 443, "result": "EINPROGRESS"}),
]  # fmt: skip


def test_analyze_replays_through_pipeline_and_grades(tmp_path: Path) -> None:
    guid = "a315bfff-7a98-403b-b442-2ea1b255e556"
    prof = profile(
        key_processes=["crond"],
        telemetry=["PROCESS_START", "NETWORK_CONNECTION"],
        modules={"rules": {"rules": ["RT002"]}, "network": {"rules": ["RT006"]},
                 "anomaly": {"rules": ["AN001"]}},
    )  # fmt: skip
    run = synthetic_run(tmp_path, guid=guid, events=CROND_EVENTS)
    settings = Settings()
    settings.security.anomaly.model_directory = str(tmp_path / "no-model")
    result = analysis.analyze(run, load_rules(None), settings, {guid: prof})
    components = {c["name"]: c for c in result["components"]}
    assert components["rules"]["grade"] == DETECTED and components["rules"]["observed"] == [
        "RT002", "RT006"]  # fmt: skip
    assert components["network"]["grade"] == DETECTED
    assert components["anomaly"]["grade"] == INCONCLUSIVE  # no model: never a detection
    assert "no trained model" in components["anomaly"]["gaps"][0]
    assert components["integrity"]["grade"] == NOT_APPLICABLE
    assert result["result"] == DETECTED and "Anomaly detector" in result["reasons"][-1]
    assert [i["incident_id"] for i in result["incidents"]] == ["INC-0001"]
    assert result["coverage"]["captured_during_execution"]["process_events"] == 2
    assert [p["process"] for p in result["runner_context"]] == ["pwsh"]
    crond = next(p for p in result["processes"] if p["process"] == "crond")
    assert crond["lineage"] == "pwsh > sh > crond"
    assert oct((run / "evaluation.json").stat().st_mode & 0o777) == "0o600"
    again = analysis.analyze(run, load_rules(None), settings, {guid: prof})  # idempotent
    assert again["pipeline"]["events_processed"] == result["pipeline"]["events_processed"] == 4
    assert [d["rule_id"] for d in again["detections"]] == ["RT002", "RT006"]


def test_missing_telemetry_is_inconclusive_not_not_detected(tmp_path: Path) -> None:
    guid = "2d7c471a-e887-4b78-b0dc-b0df1f2e0658"
    prof = profile(
        key_processes=["curl"],
        telemetry=["PROCESS_START", "NETWORK_CONNECTION"],
        modules={"rules": {"rules": ["RT006"]}, "network": {"rules": ["RT006"]}},
    )
    events = [ev(1, "PROCESS_START", 5, process_name="curl", executable_path="/usr/bin/curl")]
    run = synthetic_run(tmp_path, guid=guid, collector="proc-poll", events=events)
    result = analysis.analyze(run, load_rules(None), Settings(), {guid: prof})
    grades = {c["name"]: c["grade"] for c in result["components"]}
    assert grades["rules"] == INCONCLUSIVE and grades["network"] == INCONCLUSIVE
    assert result["result"] == INCONCLUSIVE
    gaps = next(c for c in result["components"] if c["name"] == "rules")["gaps"]
    assert "NETWORK_CONNECTION" in gaps[0]
    unreadable = profile(modules={"persistence": {"rules": ["PM002"],
                                                  "requires_readable": ["/root/x"]}})  # fmt: skip
    other = synthetic_run(tmp_path, guid="g2", run_id="atomic-x-2")
    (other / "state").mkdir()
    (other / "state" / "state-after.json").write_text(
        json.dumps({"persistence": {"status": "ok", "findings": []}})
    )
    result = analysis.analyze(other, load_rules(None), Settings(), {"g2": unreadable})
    persistence = next(c for c in result["components"] if c["name"] == "persistence")
    assert persistence["grade"] == INCONCLUSIVE and "/root/x" in persistence["gaps"][-1]


def test_execution_failure_and_unprofiled_runs(tmp_path: Path) -> None:
    run = synthetic_run(tmp_path, guid="unknown", status="FAILED", events=CROND_EVENTS)
    result = analysis.analyze(run, load_rules(None), Settings(), {})
    assert result["result"] == EXECUTION_FAILED
    assert result["detections"]  # still shown, but not a verdict
    ok = synthetic_run(tmp_path, guid="unknown", run_id="atomic-ok", events=CROND_EVENTS)
    assert analysis.analyze(ok, load_rules(None), Settings(), {})["result"] == INCONCLUSIVE


def test_benign_detections_are_false_positive_observations(tmp_path: Path) -> None:
    guid = "b04ed73c-7d43-4dc8-b563-a2fc595cba1a"
    prof = profile(benign=True, key_processes=["sh"], modules={"rules": {"rules": []}})
    run = synthetic_run(tmp_path, guid=guid, events=CROND_EVENTS)
    result = analysis.analyze(run, load_rules(None), Settings(), {guid: prof})
    fp = result["false_positive_observations"]
    assert fp["unexpected_detections"][0]["rules"] == ["RT002", "RT006"]
    summary = atomic_view.summarize([result])
    assert summary["false_positive_observations"]["benign_runs_with_detections"] == 1


# ----- execution with fake launchers (real strace when available) -----


def lab_settings(tmp_path: Path) -> Settings:
    settings = Settings()
    watched = tmp_path / "watched"
    watched.mkdir(exist_ok=True)
    security = settings.security
    security.persistence.systemd_paths = []
    security.persistence.cron_paths = []
    security.persistence.ssh_paths = []
    security.persistence.sudoers_paths = []
    security.persistence.privileged_dirs = [str(watched)]
    security.persistence.sensitive_exec_dirs = [str(watched)]
    security.integrity.paths = [str(watched)]
    security.exposure.suid_paths = [str(watched)]
    security.anomaly.model_directory = str(tmp_path / "no-model")
    return settings


def fake_launcher(command: str) -> runner.Launcher:
    """Mimics Invoke-AtomicTest: runs `sh -c command` and writes its execution-log CSV."""

    def build(log: Path) -> list[str]:
        script = (
            f"sh -c {shlex.quote(command)} & pid=$!; wait $pid; code=$?; "
            f'printf \'%s\\n\' \'"ProcessId","ExitCode"\' "\\"$pid\\",\\"$code\\"" '
            f"> {shlex.quote(str(log))}"
        )
        return ["sh", "-c", script]

    return build


def approved_preflight(
    atomics: Path, prof: Profile | None = None, **changes: Any
) -> preflight.Preflight:
    profs = {"55555555-2222-3333-4444-555555555555": prof} if prof else {}
    pre = preflight.check(env(atomics, **changes), "T1059.004", 6, profs)
    assert not pre.refusals
    return pre


@needs_strace
def test_execute_captures_evidence_without_the_monitor(
    atomics: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("the live monitor must not be started")

    monkeypatch.setattr("runtime_engine.monitor.session.MonitorSession.start", forbidden)
    monkeypatch.setattr("runtime_engine.terminal.app.run_monitor", forbidden)
    settings = lab_settings(tmp_path)
    watched = tmp_path / "watched"
    command = (f"cp /bin/true {watched}/tool; chmod 4755 {watched}/tool; "
               f"{watched}/tool; echo data > {watched}/note")  # fmt: skip
    prof = profile(
        key_processes=["tool"],
        telemetry=["PROCESS_START", "FILE_ACCESS"],
        modules={"rules": {"rules": []}, "persistence": {"rules": ["PM005"]},
                 "integrity": {"rules": ["FI002"]}, "exposure": {"rules": ["EX001"]}},
    )  # fmt: skip
    pre = approved_preflight(atomics, prof)
    results = tmp_path / "results"
    run = runner.execute(pre, settings=settings, results=results, launcher=fake_launcher(command))
    record = json.loads((run / "record.json").read_text())
    assert record["execution"]["status"] == "COMPLETED" and record["execution"]["exit_code"] == 0
    assert record["execution"]["live_monitor_used"] is False
    assert record["collection"]["collector"] == "strace"
    assert record["execution"]["executor_pid"] == record["collection"]["executor_root_pid"]
    assert oct(run.stat().st_mode & 0o777) == "0o700"
    for name in ("record.json", "events.jsonl", "trace.txt", "stdout.txt", "execution-log.csv"):
        assert oct((run / name).stat().st_mode & 0o777) == "0o600", name
    events = [json.loads(line) for line in (run / "events.jsonl").read_text().splitlines()]
    names = {e["process_name"] for e in events if e["event_type"] == "PROCESS_START"}
    assert {"sh", "cp", "chmod", "tool"} <= names
    assert any(e["metadata"].get("operation") == "chmod" for e in events)
    result = analysis.analyze(run, load_rules(None), settings, {pre.test.guid: prof})  # type: ignore[union-attr]
    grades = {c["name"]: c["grade"] for c in result["components"]}
    assert grades["persistence"] == DETECTED and grades["integrity"] == DETECTED
    assert grades["exposure"] == DETECTED and grades["rules"] == NOT_DETECTED
    assert result["result"] == PARTIAL
    assert runner.list_runs(results)[0]["result"] == PARTIAL
    assert runner.find_run(results, run.name[:20]) == run


@needs_strace
def test_nonzero_exit_and_timeout_are_execution_failures(
    atomics: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = lab_settings(tmp_path)
    pre = approved_preflight(atomics, profile(modules={"rules": {"rules": []}}))
    run = runner.execute(pre, settings=settings, results=tmp_path / "r",
                         launcher=fake_launcher("exit 3"))  # fmt: skip
    record = json.loads((run / "record.json").read_text())
    assert record["execution"]["status"] == "FAILED" and record["execution"]["exit_code"] == 3
    result = analysis.analyze(run, load_rules(None), settings, {pre.test.guid: pre.profile})  # type: ignore[union-attr,dict-item]
    assert result["result"] == EXECUTION_FAILED
    monkeypatch.setattr(runner, "TIMEOUT_GRACE", 1)
    slow = runner.execute(pre, settings=settings, results=tmp_path / "r", timeout=0,
                          launcher=lambda log: ["sleep", "30"])  # fmt: skip
    data = json.loads((slow / "record.json").read_text())
    assert data["execution"]["status"] == "TIMEOUT" and data["execution"]["timed_out"]


def test_proc_poll_fallback_without_strace(atomics: Path, tmp_path: Path) -> None:
    settings = lab_settings(tmp_path)
    pre = approved_preflight(atomics, strace=None)
    run = runner.execute(pre, settings=settings, results=tmp_path / "r",
                         launcher=fake_launcher("sleep 1"))  # fmt: skip
    record = json.loads((run / "record.json").read_text())
    assert record["collection"]["collector"] == "proc-poll" and not (run / "trace.txt").exists()
    assert any("no strace" in note for note in record["collection"]["unavailable"])
    events = [json.loads(line) for line in (run / "events.jsonl").read_text().splitlines()]
    assert any(e["process_name"] == "sleep" for e in events)  # lived long enough to poll
    with pytest.raises(runner.RunRefused):
        runner.execute(pre, settings=settings, results=tmp_path / "r", collector="strace",
                       launcher=fake_launcher("true"))  # fmt: skip
    refused = preflight.check(env(atomics), "T1059.004", 2, {})
    with pytest.raises(runner.RunRefused):
        runner.execute(refused, settings=settings, results=tmp_path / "r")


# ----- fixtures and cleanup -----


@pytest.fixture
def lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "rte-atomic-lab"
    monkeypatch.setattr(runner, "LAB_ROOT", str(root))
    monkeypatch.setattr(profiles, "LAB_ROOT", str(root))
    return root


def test_fixtures_are_created_safely_and_removed(lab: Path, tmp_path: Path) -> None:
    target = f"{lab}/T1/file.txt"
    assert runner.create_fixtures({target: "x"}) == [target]
    assert Path(target).read_text() == "x" and oct(lab.stat().st_mode & 0o777) == "0o700"
    with pytest.raises(runner.RunRefused):
        runner.create_fixtures({target: "again"})  # never overwritten
    other = tmp_path / "elsewhere"
    other.mkdir()
    (lab / "link").symlink_to(other)
    with pytest.raises(runner.RunRefused):
        runner.create_fixtures({f"{lab}/link/x": "x"})
    assert runner.remove_fixtures([target, "/etc/passwd"]) == [target]
    assert not Path(target).exists() and not (lab / "T1").exists()


def test_cleanup_runs_only_after_approval_and_verifies(
    atomics: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = lab_settings(tmp_path)
    marker = tmp_path / "watched" / "marker"
    guid = "11111111-2222-3333-4444-555555555555"
    prof = profile(
        reviewed_risk="B",
        input_args={"target": str(marker)},
        cleanup_paths=[str(marker)],
        modules={"integrity": {"rules": ["FI002"]}},
    )
    pre = preflight.check(env(atomics, strace=None), "T1059.004", 2, {guid: prof},
                          {"target": str(marker)}, allow_review_required=True)  # fmt: skip
    assert not pre.refusals and pre.cleanup == f"rm {marker}"
    results = tmp_path / "results"
    run = runner.execute(pre, settings=settings, results=results,
                         launcher=fake_launcher(pre.command))  # fmt: skip
    assert marker.exists()
    record = json.loads((run / "record.json").read_text())
    assert record["cleanup"]["status"] == "NOT RUN"  # never automatic
    # CLI: without approval (stdin is not a TTY under pytest) nothing runs.
    monkeypatch.setattr(preflight, "environment", lambda *a, **k: env(atomics, strace=None))
    profiles_file = tmp_path / "profiles.yaml"
    profiles_file.write_text(yaml.safe_dump({guid: prof.model_dump()}))
    base = ["--config", str(write_config(tmp_path)), "atomic", "cleanup", "--run-id", run.name,
            "--results-dir", str(results), "--profiles", str(profiles_file)]  # fmt: skip
    assert main(base) == 5 and marker.exists()
    assert main([*base, "--approve", "wrong"]) == 5 and marker.exists()
    monkeypatch.setattr(runner, "invoke_argv", lambda *a, **k: ["sh", "-c", pre.cleanup])
    assert main([*base, "--approve", "cleanup-11111111"]) == 0
    assert not marker.exists()
    capsys.readouterr()
    record = json.loads((run / "record.json").read_text())
    assert record["cleanup"]["status"] == "COMPLETED"
    assert record["cleanup"]["verification"] == "PASS"
    unsafe = replace(pre, profile=profile(cleanup_safe=False, cleanup_note="removes two lines"))
    with pytest.raises(runner.RunRefused):
        runner.cleanup(run, unsafe, settings=settings)


def write_config(tmp_path: Path) -> Path:
    """A config whose module paths only cover the test's temporary directory."""
    settings = lab_settings(tmp_path)
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(settings.model_dump(mode="json")))
    return path


# ----- CLI, reports, history and legacy import -----


def test_cli_inspect_run_refusals_and_dry_run(
    atomics: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(preflight, "environment", lambda *a, **k: env(atomics))
    results = tmp_path / "results"
    common = ["--results-dir", str(results), "--profiles", str(tmp_path / "none.yaml")]
    assert main(["atomic", "inspect", "T1059.004", "--test-number", "2", "--json", *common]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["command"] == "echo atomic > /tmp/x.txt" and data["refusals"]
    assert main(["atomic", "run", "T1059.004", "--test-number", "2", *common]) == 4
    assert main(["atomic", "run", "T1059.004", "--test-number", "6", *common]) == 5
    assert main(["atomic", "run", "T1059.004", "--test-number", "6", "--approve", "nope",
                 *common]) == 5  # fmt: skip
    assert main(["atomic", "run", "T1059.004", "--test-number", "6", "--approve", "55555555",
                 "--dry-run", *common]) == 0  # fmt: skip
    assert not results.exists()  # nothing was executed or recorded
    assert main(["atomic", "inspect", "T1059.004"]) == 1  # missing --test-number
    assert main(["atomic", "report", "--run-id", "missing", *common]) == 3
    capsys.readouterr()
    assert main(["atomic", "inspect", "T1059.004", "--test-number", "5", *common]) == 0
    text = capsys.readouterr().out
    assert "REFUSED" in text and "crontab /tmp/evil" in text


@needs_strace
def test_cli_run_end_to_end_with_fake_runner(
    atomics: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("the live monitor must not be started")

    monkeypatch.setattr("runtime_engine.terminal.app.run_monitor", forbidden)
    monkeypatch.setattr(preflight, "environment", lambda *a, **k: env(atomics))
    monkeypatch.setattr(
        runner, "invoke_argv", lambda pwsh, at, test, log, *a, **k: fake_launcher("uname -s")(log)
    )
    results = tmp_path / "results"
    common = ["--config", str(write_config(tmp_path)), "atomic"]
    paths = ["--results-dir", str(results), "--profiles", str(tmp_path / "none.yaml")]
    assert main([*common, "run", "T1059.004", "--test-number", "6", "--approve", "55555555",
                 "--json", *paths]) == 0  # fmt: skip
    payload = json.loads(capsys.readouterr().out)
    assert payload["evaluation"]["result"] == INCONCLUSIVE  # no reviewed profile
    run_id = payload["evaluation"]["run_id"]
    assert main([*common, "runs", "--json", *paths]) == 0
    assert json.loads(capsys.readouterr().out)[0]["run_id"] == run_id
    assert main([*common, "report", "--run-id", run_id, *paths]) == 0
    report = capsys.readouterr().out
    for section in ("ATOMIC RED TEAM - EDR EVALUATION", "EVIDENCE COLLECTION",
                    "DETECTION RESULTS BY COMPONENT", "EVIDENCE GAPS", "CLEANUP"):  # fmt: skip
        assert section in report
    assert main([*common, "analyze", "--run-id", run_id[:25], "--json", *paths]) == 0
    capsys.readouterr()
    assert main([*common, "summary", *paths]) == 0
    summary = capsys.readouterr().out
    assert "EVALUATION SUMMARY" in summary and "%" not in summary.split("RUNS")[0]


def test_summary_counts_without_accuracy_percentages(tmp_path: Path) -> None:
    evaluations = []
    for index, (status, events) in enumerate((("COMPLETED", CROND_EVENTS), ("FAILED", []))):
        guid = "a315bfff-7a98-403b-b442-2ea1b255e556"
        run = synthetic_run(tmp_path, guid=guid, status=status, events=events,
                            run_id=f"atomic-{index}")  # fmt: skip
        prof = profile(key_processes=["crond"], modules={"rules": {"rules": ["RT002"]}})
        evaluations.append(analysis.analyze(run, load_rules(None), Settings(), {guid: prof}))
    summary = atomic_view.summarize(evaluations)
    assert summary["execution_coverage"] == {"attempted": 2, "executed_successfully": 1,
                                             "failed": 1}  # fmt: skip
    assert summary["detection_outcomes"]["DETECTED"] == 1
    assert summary["detection_outcomes"]["EXECUTION FAILED"] == 1
    assert "accuracy" not in json.dumps(summary).replace("not an accuracy", "")
    assert atomic_view.render_runs([]) is not None


def test_legacy_import_reanalyzes_previous_monitor_evidence(tmp_path: Path) -> None:
    database = Database(tmp_path / "engine.db")
    pipeline = Pipeline(database, load_rules(None))
    start = datetime(2026, 1, 1, 0, 0, 10, tzinfo=UTC)

    def event(pid: int, ppid: int | None, name: str, seconds: float) -> Event:
        return Event(
            event_id=f"legacy-{pid}",
            timestamp=start + timedelta(seconds=seconds),
            event_type="PROCESS_START",
            pid=pid,
            ppid=ppid,
            process_name=name,
            process_start_time=str(pid * 10),
            parent_start_time=str(ppid * 10) if ppid else None,
            host_id="boot",
            source="proc",
        )

    for item in (event(1, None, "pwsh", -5), event(2, 1, "sh", 1), event(3, 2, "sleep", 2),
                 event(9, None, "unrelated", 2), event(4, 2, "sleep", 60)):  # fmt: skip
        pipeline.process(item)
    database.close()
    old = tmp_path / "old-run"
    old.mkdir()
    (old / "record.json").write_text(json.dumps({
        "run_id": "OLD", "guid": "b04ed73c-7d43-4dc8-b563-a2fc595cba1a", "technique": "T1059.004",
        "test_number": 8, "test_name": "Command line scripts", "executor": "sh",
        "risk_class": "A SAFE", "command": "loop", "start_utc": "2026-01-01T00:00:10Z",
        "end_utc": "2026-01-01T00:00:15Z", "runner": {"pid": 1, "key": '["boot",1,"10"]'},
        "execution": {"status": "COMPLETED", "exit_code": 0, "executor_pid": 2},
        "cleanup": {"status": "NOT REQUIRED"}, "engine": {"poll_interval_seconds": 2.0},
    }))  # fmt: skip
    (old / "test-output.txt").write_text("1, Atomic Red Team was here!\n")
    run = runner.import_legacy(old, tmp_path / "engine.db", tmp_path / "results")
    lines = (run / "events.jsonl").read_text().splitlines()
    assert [json.loads(line)["process_name"] for line in lines] == ["pwsh", "sh", "sleep"]
    guid = "b04ed73c-7d43-4dc8-b563-a2fc595cba1a"
    profs = profiles.load_profiles(Path("testing/atomic-red-team/expectations.yaml"))
    result = analysis.analyze(run, load_rules(None), Settings(), profs)
    assert result["result"] == NOT_DETECTED and result["test"]["guid"] == guid
    assert "coverage gap" in result["components"][0]["reasons"][0]
    assert runner.list_runs(tmp_path / "results")[0]["kind"] == "imported"
    with pytest.raises(KeyError):
        runner.import_legacy(tmp_path, tmp_path / "engine.db", tmp_path / "results")
    with sqlite3.connect(tmp_path / "engine.db") as connection:  # read-only access
        assert connection.execute("SELECT count(*) FROM events").fetchone()[0] == 5


def test_find_run_rejects_paths_and_ambiguity(tmp_path: Path) -> None:
    for name in ("atomic-a1", "atomic-a2"):
        synthetic_run(tmp_path, guid="g", run_id=name)
    with pytest.raises(KeyError):
        runner.find_run(tmp_path, "atomic-a")
    with pytest.raises(KeyError):
        runner.find_run(tmp_path, "../etc")
    assert runner.find_run(tmp_path, "atomic-a1").name == "atomic-a1"
