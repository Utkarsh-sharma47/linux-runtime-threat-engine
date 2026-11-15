"""`atomic` commands: offline Atomic Red Team evaluation and live synthetic acceptance.

Offline actions do not need the live monitor. `live-accept` starts a short-lived
MonitorSession, registers a fake Atomic session, and feeds clearly labeled SYNTHETIC
telemetry through the shared pipeline. It never executes a real Atomic attack.
"""

import argparse
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.console import Console

from runtime_engine.atomic import analysis, preflight, runner
from runtime_engine.atomic.evidence import read_json
from runtime_engine.atomic.live import (
    LiveAtomicBridge,
    synthetic_network_event,
    synthetic_process_event,
)
from runtime_engine.atomic.profiles import (
    ModuleExpectation,
    Profile,
    load_profiles,
    parse_overrides,
)
from runtime_engine.config.settings import Settings
from runtime_engine.detection.rule_loader import Rule
from runtime_engine.monitor.session import MonitorSession
from runtime_engine.monitor.state import DashboardState, SessionInfo, Verbosity
from runtime_engine.pipeline import Pipeline
from runtime_engine.security import ransomware_sim
from runtime_engine.storage.database import Database
from runtime_engine.terminal.views import atomic_view

EXIT_REFUSED = 4
EXIT_NOT_APPROVED = 5


def emit(data: Any) -> None:
    print(json.dumps(data, indent=2, default=str))


def approved(token: str, given: str | None, console: Console, what: str) -> bool:
    if given is not None:
        return given.strip() == token
    if not sys.stdin.isatty():
        print(
            f"refused: explicit approval required; pass --approve {token} after reviewing "
            "the output above",
            file=sys.stderr,
        )
        return False
    answer = console.input(f"Type '{token}' to {what}, anything else to abort: ")
    return answer.strip() == token


def check(args: argparse.Namespace, profiles: dict[str, Any], **flags: bool) -> preflight.Preflight:
    env = preflight.environment(args.atomics)
    return preflight.check(
        env, args.technique, args.test_number, profiles, parse_overrides(args.input_arg), **flags
    )


def show_report(run: Path, console: Console, as_json: bool) -> int:
    evaluation = read_json(run / "evaluation.json")
    record = read_json(run / "record.json") or {}
    if evaluation is None:
        print(f"run {run.name} has not been analyzed: atomic analyze --run-id {run.name}",
              file=sys.stderr)  # fmt: skip
        return 3
    if as_json:
        emit({"evaluation": evaluation, "record": record})
    else:
        console.print(atomic_view.render_report(evaluation, record))
    return 0


def command(
    args: argparse.Namespace, settings: Settings, rules: list[Rule], console: Console
) -> int:
    profiles = load_profiles(args.profiles)
    results: Path = args.results_dir
    action = args.action
    if action == "inspect":
        pre = check(args, profiles)
        if args.json:
            emit(pre.as_dict())
        else:
            console.print(atomic_view.render_inspect(pre.as_dict()))
        return 0
    if action == "run":
        pre = check(
            args,
            profiles,
            allow_review_required=args.allow_review_required,
            isolated_vm=args.isolated_vm,
            prereqs_reviewed=args.prereqs_reviewed,
        )
        if not args.json:
            console.print(atomic_view.render_inspect(pre.as_dict()))
        if pre.refusals or pre.test is None:
            if args.json:
                emit(pre.as_dict())
            print("refused: " + "; ".join(pre.refusals), file=sys.stderr)
            return EXIT_REFUSED
        if not approved(pre.token, args.approve, console, "execute exactly this test"):
            print("not approved: nothing was executed", file=sys.stderr)
            return EXIT_NOT_APPROVED
        if args.dry_run:
            console.print("DRY RUN: validated and approved; nothing was executed.")
            return 0
        run = runner.execute(
            pre,
            settings=settings,
            results=results,
            collector=args.collector,
            timeout=args.timeout,
            watch_dirs=args.watch_dir,
        )
        analysis.analyze(run, rules, settings, profiles)
        return show_report(run, console, args.json)
    if action == "analyze":
        run = runner.find_run(results, args.run_id)
        analysis.analyze(run, rules, settings, profiles)
        return show_report(run, console, args.json)
    if action == "report":
        return show_report(runner.find_run(results, args.run_id), console, args.json)
    if action == "runs":
        runs = runner.list_runs(results)
        if args.json:
            emit(runs)
        else:
            console.print(atomic_view.render_runs(runs))
        return 0
    if action == "summary":
        evaluations = [
            e
            for r in runner.list_runs(results)
            if (e := read_json(Path(r["path"]) / "evaluation.json")) is not None
        ]
        summary = atomic_view.summarize(evaluations)
        if args.json:
            emit(summary)
        else:
            console.print(atomic_view.render_summary(summary))
        return 0
    if action == "cleanup":
        return cleanup(args, settings, rules, profiles, console)
    if action == "simulate":
        return simulate(args, settings, rules, profiles, console)
    if action == "import-legacy":
        if args.dir is None or args.engine_db is None:
            raise ValueError("import-legacy needs --dir and --engine-db")
        run = runner.import_legacy(args.dir, args.engine_db, results)
        analysis.analyze(run, rules, settings, profiles)
        return show_report(run, console, args.json)
    if action == "live-accept":
        return live_accept(args, settings, rules, console)
    raise ValueError(f"unknown atomic action {action}")


class _IdleCollector:
    """Polls nothing; live-accept injects synthetic events via submit_event."""

    errors = 0
    rejected = 0
    missing_telemetry = 0
    read_failures = 0

    def collect(self):  # type: ignore[no-untyped-def]
        return iter(())


def live_accept(
    args: argparse.Namespace, settings: Settings, rules: list[Rule], console: Console
) -> int:
    """Demonstrate the full live path with a fake profile and SYNTHETIC telemetry only."""
    db_path = args.engine_db or Path("testing/reports/live-accept.db")
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()
    database = Database(db_path)
    info = SessionInfo(
        session_id="SES-LIVE-ACCEPT",
        mode="LIVE",
        hostname="synthetic-accept",
        kernel="test",
        engine_pid=0,
        started_at=datetime.now(UTC),
        verbosity=Verbosity.NORMAL,
        poll_interval=0.05,
        queue_capacity=200,
        window_seconds=settings.correlation_window_seconds,
        telemetry="synthetic injection (no /proc); NOT real host Atomic activity",
        database_path=str(db_path),
        reports_directory=str(args.results_dir),
    )
    state = DashboardState(info)
    pipeline = Pipeline(database, rules, settings.correlation_window_seconds)
    session = MonitorSession(
        pipeline,
        _IdleCollector(),
        state,
        poll_interval=0.05,
        queue_capacity=200,
    )
    bridge = LiveAtomicBridge(session, database)
    session.start()
    try:
        record = bridge.register(
            technique="T1071.001",
            test_number=99,
            guid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            name="Fake Atomic profile (synthetic acceptance)",
            synthetic=True,
        )
        host = "synthetic-host"
        start = "9001"
        events = [
            synthetic_process_event(
                pid=4242,
                name="curl",
                exe="/tmp/curl",
                start=start,
                host_id=host,
                ppid=1111,
                parent_name="bash",
                parent_start="8000",
            ),
            synthetic_network_event(
                pid=4242,
                name="curl",
                start=start,
                destination="203.0.113.10",
                host_id=host,
            ),
        ]
        stats = bridge.ingest(record.run_id, events)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and state.counters.processed < stats["accepted"]:
            time.sleep(0.01)
        bridge.finish(record.run_id, "COMPLETED")
        profile = Profile(
            technique="T1071.001",
            name="Synthetic live acceptance profile",
            expected_rules=["RT002", "RT005", "RT006"],
            telemetry=["PROCESS_START", "NETWORK_CONNECTION"],
            rationale="Acceptance-only fake profile; never a real Atomic test.",
            reviewed_risk="A",
            modules={"rules": ModuleExpectation(rules=["RT002", "RT005", "RT006"])},
        )
        evaluation = bridge.evaluate(record.run_id, profile)
        snap = state.snapshot(log_limit=0)
        result = {
            "evidence_label": "SYNTHETIC",
            "note": "All evidence is synthetic; no real Atomic attack was executed.",
            "collectors": bridge.verify_collectors(),
            "ingest": stats,
            "dashboard": {
                "processed": snap.counters.processed,
                "rule_matches": snap.counters.rule_matches,
                "incidents": len(snap.incidents),
                "atomic_sessions": snap.atomic_sessions,
            },
            "evaluation": evaluation,
            "database": str(db_path),
        }
        if args.json:
            emit(result)
        else:
            console.print_json(json.dumps(result, default=str))
        return 0 if evaluation["overall"]["grade"] == "DETECTED" else 1
    finally:
        session.shutdown("user_quit")
        database.close()


def simulate(
    args: argparse.Namespace,
    settings: Settings,
    rules: list[Rule],
    profiles: dict[str, Any],
    console: Console,
) -> int:
    if args.technique != "ransomware":
        raise ValueError("atomic simulate supports: ransomware")
    env = preflight.environment(args.atomics, probe_module=False)
    pre = preflight.Preflight(env, None, None, {})
    if env.uid == 0:
        pre.refusals.append("running as root: the workflow never runs simulations as root")
    lab = ransomware_sim.create_lab()
    pre = runner.simulator_preflight(pre, lab, args.files, 0.03, profiles)
    if not args.json:
        console.print(atomic_view.render_inspect(pre.as_dict()))
    if pre.refusals or not approved(pre.token, args.approve, console, "run the simulator"):
        ransomware_sim.cleanup(lab)
        print("not run: the empty lab was removed", file=sys.stderr)
        return EXIT_REFUSED if pre.refusals else EXIT_NOT_APPROVED
    if args.dry_run:
        ransomware_sim.cleanup(lab)
        console.print("DRY RUN: validated and approved; nothing was executed.")
        return 0
    command = [sys.executable, "-m", "runtime_engine.security.ransomware_sim", str(lab),
               "--files", str(args.files), "--delay", "0.03"]  # fmt: skip
    run = runner.execute(
        pre,
        settings=settings,
        results=args.results_dir,
        collector=args.collector,
        timeout=args.timeout,
        watch_dirs=[str(lab)],
        launcher=lambda _: command,
        execution_log=False,
        extra={"simulator": {"lab": str(lab), "files": args.files}},
    )
    analysis.analyze(run, rules, settings, profiles)
    return show_report(run, console, args.json)


def cleanup(
    args: argparse.Namespace,
    settings: Settings,
    rules: list[Rule],
    profiles: dict[str, Any],
    console: Console,
) -> int:
    run = runner.find_run(args.results_dir, args.run_id)
    record = read_json(run / "record.json") or {}
    if record.get("schema") != runner.RECORD_SCHEMA or record.get("imported_from"):
        print("refused: cleanup is only available for runs executed by `atomic run`",
              file=sys.stderr)  # fmt: skip
        return EXIT_REFUSED
    test = record["test"]
    if test["guid"] == runner.SIMULATOR_GUID:
        console.print(
            f"Simulator cleanup: removes only simulator files in {record['simulator']['lab']}"
        )
        if not approved("cleanup-simulator", args.approve, console, "remove the simulator lab"):
            print("not approved: cleanup was not run", file=sys.stderr)
            return EXIT_NOT_APPROVED
        result = runner.cleanup_simulator(run, settings, profiles)
        analysis.analyze(run, rules, settings, profiles)
        if args.json:
            emit(result)
        else:
            console.print_json(json.dumps(result, default=str))
        return 0 if result.get("verification") == "PASS" else 1
    env = preflight.environment(args.atomics)
    pre = preflight.check(
        env, test["technique"], test["number"], profiles, test["overrides"],
        allow_review_required=True, isolated_vm=True, prereqs_reviewed=True,
    )  # fmt: skip
    if pre.test is None or pre.test.guid != test["guid"]:
        print("refused: the test definition changed since the run", file=sys.stderr)
        return EXIT_REFUSED
    if pre.cleanup != test["cleanup"]:
        print("refused: the rendered cleanup command differs from the run record",
              file=sys.stderr)  # fmt: skip
        return EXIT_REFUSED
    console.print(atomic_view.block("CLEANUP COMMAND (exact)", atomic_view.code(pre.cleanup)))
    if pre.profile is not None:
        safety = "reviewed safe" if pre.profile.cleanup_safe else "reviewed UNSAFE"
        console.print(f"Profile: {safety}. {pre.profile.cleanup_note}")
    fixtures = record.get("fixtures", [])
    if fixtures:
        console.print(
            "Lab fixtures created by the workflow, removed afterwards: " + ", ".join(fixtures)
        )
    if not pre.cleanup.strip() and not fixtures:
        result = runner.cleanup(run, pre, settings=settings)
        console.print(
            f"This test defines no cleanup command. Verification: {result['verification']}"
        )
        return 0 if result.get("verification") == "PASS" else 1
    token = f"cleanup-{test['guid'][:8]}"
    if not approved(token, args.approve, console, "run exactly this cleanup command"):
        print("not approved: cleanup was not run", file=sys.stderr)
        return EXIT_NOT_APPROVED
    try:
        result = runner.cleanup(run, pre, settings=settings, timeout=args.timeout)
    except runner.RunRefused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    analysis.analyze(run, rules, settings, profiles)
    if args.json:
        emit(result)
    else:
        console.print_json(json.dumps(result, default=str))
    return 0 if result.get("verification") == "PASS" else 1


def add_parser(sub: Any) -> None:
    atomic = sub.add_parser(
        "atomic",
        help="Atomic Red Team evaluation (offline) and live synthetic acceptance",
        description="Inspect, run (approved tests only, traced with strace), analyze offline "
        "with the engine's pipeline and security modules, and report. Use live-accept for a "
        "SYNTHETIC end-to-end live-monitor demonstration (never executes a real Atomic attack). "
        "Results default to ~/AtomicRedTeam/lab-results.",
    )
    atomic.add_argument(
        "action",
        choices=["inspect", "run", "analyze", "report", "runs", "summary", "cleanup",
                 "simulate", "import-legacy", "live-accept"],
    )  # fmt: skip
    atomic.add_argument("technique", nargs="?", help="ATT&CK technique, e.g. T1059.004")
    atomic.add_argument("--test-number", type=int, help="1-based test number in the YAML")
    atomic.add_argument(
        "--input-arg", action="append", default=[], metavar="NAME=VALUE",
        help="reviewed input argument override (repeatable)",
    )  # fmt: skip
    atomic.add_argument("--run-id", help="run ID or unique prefix (analyze, report, cleanup)")
    atomic.add_argument("--approve", metavar="TOKEN", help="approval token shown by inspect")
    atomic.add_argument("--allow-review-required", action="store_true",
                        help="allow risk class B after reviewing the commands")  # fmt: skip
    atomic.add_argument("--isolated-vm", action="store_true",
                        help="allow class C, only inside a detected virtual machine")  # fmt: skip
    atomic.add_argument("--prereqs-reviewed", action="store_true",
                        help="prerequisites were reviewed and satisfied manually")  # fmt: skip
    atomic.add_argument("--collector", choices=["auto", "strace", "proc"], default="auto")
    atomic.add_argument("--timeout", type=int, default=120)
    atomic.add_argument("--watch-dir", action="append", default=[],
                        help="extra directory for the ransomware watch (repeatable)")  # fmt: skip
    atomic.add_argument("--dry-run", action="store_true", help="validate and approve only")
    atomic.add_argument("--files", type=int, default=30, help="simulator file count (max 200)")
    atomic.add_argument("--atomics", type=Path, default=preflight.DEFAULT_ATOMICS)
    atomic.add_argument("--results-dir", type=Path, default=runner.DEFAULT_RESULTS)
    atomic.add_argument("--profiles", type=Path, help="expectation profiles YAML")
    atomic.add_argument("--dir", type=Path, help="earlier lab run directory (import-legacy)")
    atomic.add_argument("--engine-db", type=Path, help="its monitor database (import-legacy)")
    atomic.add_argument("--json", action="store_true")


def validate(args: argparse.Namespace) -> None:
    needs_test = args.action in ("inspect", "run")
    if needs_test and (args.technique is None or args.test_number is None):
        raise ValueError(f"atomic {args.action} needs TECHNIQUE and --test-number")
    if args.action in ("analyze", "report", "cleanup") and not args.run_id:
        raise ValueError(f"atomic {args.action} needs --run-id")
    if args.action == "simulate" and args.technique is None:
        raise ValueError("atomic simulate needs a scenario: ransomware")
    if args.timeout < 5 or args.timeout > 3600:
        raise ValueError("--timeout must be between 5 and 3600 seconds")
