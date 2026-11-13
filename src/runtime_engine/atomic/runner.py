"""Stage B: run ONE approved Atomic test without the live monitor and capture evidence.

The official Invoke-AtomicTest runs the test (selected by GUID) under strace in a
private run directory. Prerequisites and cleanup are never run here; cleanup is a
separate, separately approved step (`cleanup()`), verified against the baselines taken
before the test. Results: <results>/<run_id>/ (mode 0700, files 0600).
"""

import csv
import json
import os
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from runtime_engine.atomic import trace as tracing
from runtime_engine.atomic.catalog import AtomicTest
from runtime_engine.atomic.evidence import (
    DuringCollector,
    StateCollector,
    read_json,
    write_private,
)
from runtime_engine.atomic.preflight import Preflight
from runtime_engine.atomic.profiles import LAB_ROOT, Profile
from runtime_engine.config.settings import Settings
from runtime_engine.events.schema import Event
from runtime_engine.security.ransomware import RansomwareMonitor

RECORD_SCHEMA = "rte-atomic-run/1"
DEFAULT_RESULTS = Path(
    os.environ.get("RTE_ATOMIC_RESULTS", Path.home() / "AtomicRedTeam" / "lab-results")
)
Launcher = Callable[[Path], list[str]]
TIMEOUT_GRACE = 60  # seconds beyond Invoke-AtomicTest's own -TimeoutSeconds
UNAVAILABLE_ALWAYS = [
    "kernel audit/eBPF telemetry: not used (auditd is not installed and eBPF needs root)",
    "processes outside the test's process tree (for example cron or systemd running "
    "installed persistence later) are not traced",
    "file contents, written data and packet payloads are never recorded",
]


SIMULATOR_GUID = "simulator-ransomware"


class RunRefused(Exception):
    """The run was refused before anything executed."""


def run_settings(settings: Settings, profile: Profile | None) -> Settings:
    """Settings for one run: the reviewed profile may add paths to module configuration."""
    if profile is None or not profile.module_paths:
        return settings
    copy = settings.model_copy(deep=True)
    for key, paths in profile.module_paths.items():
        module, attribute = key.split(".")
        target = getattr(copy.security, module)
        current = list(getattr(target, attribute))
        setattr(target, attribute, current + [p for p in paths if p not in current])
    return copy


def lab_root() -> Path:
    root = Path(LAB_ROOT)
    if root.is_symlink():
        raise RunRefused(f"{root} is a symlink; refusing to use it")
    root.mkdir(mode=0o700, exist_ok=True)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise RunRefused(f"{root} is not a directory owned by this user")
    return root


def create_fixtures(fixtures: dict[str, str]) -> list[str]:
    """Create reviewed lab-only test targets; never overwrite anything."""
    if not fixtures:
        return []
    root = lab_root()
    created = []
    for path, content in sorted(fixtures.items()):
        target = Path(path)
        current = root
        for part in target.relative_to(root).parts[:-1]:
            current = current / part
            if current.is_symlink():
                raise RunRefused(f"{current} is a symlink; refusing to create fixtures")
            current.mkdir(mode=0o700, exist_ok=True)
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        except FileExistsError as exc:
            raise RunRefused(
                f"lab fixture {target} already exists from an earlier run: run "
                "`atomic cleanup` for that run (or remove it) first"
            ) from exc
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
        created.append(path)
    return created


def remove_fixtures(paths: list[str]) -> list[str]:
    """Remove fixture files this user owns, then empty lab directories."""
    removed = []
    for path in paths:
        target = Path(path)
        if not str(target).startswith(LAB_ROOT + "/"):
            continue
        try:
            info = target.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid():
            target.unlink()
            removed.append(path)
    for path in sorted({str(Path(p).parent) for p in paths}, key=len, reverse=True):
        current = Path(path)
        while str(current).startswith(LAB_ROOT):
            try:
                current.rmdir()
            except OSError:
                break
            current = current.parent
    return removed


def quote_ps(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def invoke_argv(
    pwsh: str,
    atomics: Path,
    test: AtomicTest,
    log: Path | None,
    timeout: int,
    overrides: dict[str, str],
    *,
    cleanup: bool = False,
) -> list[str]:
    call = (
        f"Invoke-AtomicTest {quote_ps(test.technique)} -TestGuids {quote_ps(test.guid)} "
        f"-PathToAtomicsFolder {quote_ps(str(atomics))} -TimeoutSeconds {int(timeout)}"
    )
    if cleanup:
        call += " -Cleanup -NoExecutionLog"
    elif log is not None:
        call += f" -ExecutionLogPath {quote_ps(str(log))} -LoggingModule 'Default-ExecutionLogger'"
    if overrides:
        pairs = "; ".join(f"{name} = {quote_ps(value)}" for name, value in overrides.items())
        call += f" -InputArgs @{{{pairs}}}"
    script = "; ".join(
        [
            "$ErrorActionPreference = 'Stop'",
            "$ProgressPreference = 'SilentlyContinue'",
            "Import-Module invoke-atomicredteam -ErrorAction Stop",
            call,
        ]
    )
    return [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script]


def private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def read_execution_log(path: Path) -> tuple[int | None, int | None]:
    """(executor PID, exit code) from Invoke-AtomicTest's Default-ExecutionLogger CSV."""
    if not path.is_file():
        return None, None
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    if not rows:
        return None, None
    row = rows[-1]
    try:
        return int(row["ProcessId"]), int(row["ExitCode"])
    except (KeyError, ValueError):
        return None, None


def launch(argv: list[str], cwd: Path, out: Path, err: Path, timeout: float) -> tuple[int, bool]:
    """Run argv in its own session; kill the whole group on timeout. (exit code, timed out)."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    with (
        os.fdopen(os.open(out, flags, 0o600), "wb") as stdout,
        os.fdopen(os.open(err, flags, 0o600), "wb") as stderr,
    ):
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
        try:
            return process.wait(timeout), False
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            return process.wait(10), True


def required_paths(profile: Profile | None) -> list[str]:
    if profile is None:
        return []
    return sorted({p for e in profile.expectations().values() for p in e.requires_readable})


def execute(
    pre: Preflight,
    *,
    settings: Settings,
    results: Path = DEFAULT_RESULTS,
    collector: str = "auto",
    timeout: int = 120,
    watch_dirs: list[str] | None = None,
    launcher: Launcher | None = None,
    execution_log: bool = True,
    extra: dict[str, Any] | None = None,
) -> Path:
    """Execute an approved, validated test and capture evidence. Returns the run directory.

    `execution_log=False` (the simulator) takes the exit code from the launched process
    instead of Invoke-AtomicTest's execution log.
    """
    if pre.refusals or pre.test is None:
        raise RunRefused("; ".join(pre.refusals) or "no test selected")
    test, env, profile = pre.test, pre.environment, pre.profile
    settings = run_settings(settings, profile)
    if collector == "strace" and not env.tracing:
        raise RunRefused("strace tracing was requested but is not available")
    use_trace = collector in ("auto", "strace") and env.tracing
    if launcher is None:
        if env.pwsh is None:
            raise RunRefused("pwsh not found")
        pwsh = env.pwsh

        def launcher(log: Path) -> list[str]:
            return invoke_argv(pwsh, Path(env.atomics), test, log, timeout, pre.overrides)

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"atomic-{stamp}-{test.technique}-{test.number}-{test.guid[:8]}"
    run = private_dir(private_dir(results) / run_id)
    workdir = private_dir(run / "workdir")
    fixtures = create_fixtures(profile.fixtures if profile else {})
    integrity_paths = list(settings.security.integrity.paths)
    ransomware_dirs = list(profile.watch_ransomware if profile else []) + list(watch_dirs or [])
    if profile:
        integrity_paths += [p for p in profile.watch_integrity if p not in integrity_paths]
    integrity_paths = [os.path.expanduser(p) for p in integrity_paths]
    state = StateCollector(settings, private_dir(run / "state"), integrity_paths)
    state.before()
    readability = {
        p: os.access(os.path.expanduser(p), os.R_OK) for p in required_paths(profile)
    }  # fmt: skip
    ransomware = (
        RansomwareMonitor(settings.security.ransomware, directories=ransomware_dirs)
        if ransomware_dirs
        else None
    )
    during = DuringCollector(os.getpid(), poll_events=not use_trace, ransomware=ransomware)
    log = run / "execution-log.csv"
    argv = launcher(log)
    if use_trace:
        argv = tracing.strace_argv(run / "trace.txt", argv)
    started = datetime.now(UTC)
    clock = time.monotonic()
    during.start()
    try:
        code, timed_out = launch(
            argv, workdir, run / "stdout.txt", run / "stderr.txt", timeout + TIMEOUT_GRACE
        )
    finally:
        during.finish()
        if ransomware is not None:
            ransomware.close()
    ended = datetime.now(UTC)
    duration = time.monotonic() - clock
    state.after()
    executor_pid, exit_code = read_execution_log(log) if execution_log else (None, code)
    if timed_out:
        status = "TIMEOUT"
    elif exit_code is None:
        status = "FAILED"
    else:
        status = "COMPLETED" if exit_code == 0 else "FAILED"
    unavailable = list(UNAVAILABLE_ALWAYS)
    stats: dict[str, Any] = {}
    runner_pids: set[int] = {os.getpid()}
    root_pid: int | None = None
    if use_trace and (run / "trace.txt").is_file():
        os.chmod(run / "trace.txt", 0o600)
        with (run / "trace.txt").open(encoding="utf-8", errors="replace") as stream:
            parsed = tracing.parse(stream)
        conversion = tracing.to_events(parsed, run_id=run_id, root=executor_pid, uid=env.uid)
        events = conversion.events
        stats = conversion.stats | {"traced_processes_total": len(parsed.processes)}
        root_pid = conversion.root
        runner_pids |= {p for p in (parsed.first_pid, conversion.runner) if p is not None}
        if executor_pid is None:
            unavailable.append(
                "executor PID unknown (no execution log): the whole runner tree was attributed"
            )
        if pre.setuid_programs:
            unavailable.append(
                "set-ID programs ran without privileges under tracing: "
                + ", ".join(pre.setuid_programs)
            )
    else:
        events = list(during.events.values())
        for event in events:
            if event.get("ppid") == os.getpid():
                event["metadata"]["role"] = "atomic-runner (context, not part of the test)"
        root_pid = executor_pid
        unavailable += [
            "no strace: only /proc polling every 0.25 s; processes shorter than that are missed",
            "no FILE_ACCESS, NETWORK_CONNECTION or PRIVILEGE_CHANGE events without tracing",
        ]
    tracing.write_jsonl(events, run / "events.jsonl")
    samples = keep_test_samples(list(during.samples.values()), root_pid, runner_pids)
    write_private(run / "anomaly-samples.json", samples)
    if during.ransomware_reports:
        best = max(
            during.ransomware_reports,
            key=lambda r: (len(r.findings), max_score(r.summary)),
        )
        write_private(run / "ransomware.json", best.as_dict())
    cleanup_status = "NOT REQUIRED" if not pre.cleanup.strip() else "NOT RUN"
    record = {
        "schema": RECORD_SCHEMA,
        "run_id": run_id,
        "created_at": started.isoformat(),
        "test": test_record(pre),
        "environment": vars(env) | {"tracing": env.tracing},
        "execution": {
            "status": status,
            "exit_code": exit_code,
            "executor_pid": executor_pid,
            "runner_exit_code": code,
            "timed_out": timed_out,
            "start_utc": started.isoformat(),
            "end_utc": ended.isoformat(),
            "duration_seconds": round(duration, 3),
            "timeout_seconds": timeout,
            "stdout": "stdout.txt",
            "stderr": "stderr.txt",
            "execution_log": "execution-log.csv" if log.is_file() else None,
            "workdir": "workdir",
            "live_monitor_used": False,
        },
        "collection": {
            "collector": "strace" if use_trace else "proc-poll",
            "trace_file": "trace.txt" if use_trace else None,
            "events_file": "events.jsonl",
            "events": len(events),
            "trace_stats": stats,
            "executor_root_pid": root_pid,
            "during": {
                "passes": during.passes,
                "errors": during.errors,
                "anomaly_samples": len(samples),
            },
            "integrity_paths": integrity_paths,
            "ransomware_watch": ransomware_dirs,
            "readability": readability,
            "module_paths": profile.module_paths if profile else {},
            "unavailable": unavailable,
        },
        "fixtures": fixtures,
        "cleanup": {
            "status": cleanup_status,
            "command": pre.cleanup,
            "reviewed_safe": profile.cleanup_safe if profile else None,
            "note": profile.cleanup_note if profile else "",
        },
    }
    record.update(extra or {})
    write_private(run / "record.json", record)
    if log.is_file():
        os.chmod(log, 0o600)
    return run


def max_score(summary: dict[str, Any]) -> float:
    directories = summary.get("directories") or {}
    return max((float(d.get("score", 0)) for d in directories.values()), default=0.0)


def keep_test_samples(
    samples: list[dict[str, Any]], root: int | None, runner: set[int]
) -> list[dict[str, Any]]:
    """Anomaly samples of the executor and its descendants only (not strace or pwsh)."""
    if root is None:
        return [s for s in samples if s["pid"] not in runner and s["process"] != "strace"]
    keep, changed = {root}, True
    parents = {s["pid"]: s["ppid"] for s in samples}
    while changed:
        changed = False
        for pid, ppid in parents.items():
            if ppid in keep and pid not in keep:
                keep.add(pid)
                changed = True
    return [s for s in samples if s["pid"] in keep]


def test_record(pre: Preflight) -> dict[str, Any]:
    test = pre.test
    assert test is not None
    return {
        "technique": test.technique,
        "technique_name": test.technique_name,
        "number": test.number,
        "name": test.name,
        "guid": test.guid,
        "executor": test.executor,
        "elevation_required": test.elevation_required,
        "risk": pre.risk,
        "risk_source": pre.risk_source,
        "overrides": pre.overrides,
        "command": pre.command,
        "cleanup": pre.cleanup,
        "prerequisites": len(test.dependencies),
        "profile": pre.profile is not None,
    }


def outside_lab(after: dict[str, Any]) -> dict[str, Any]:
    """State differences that remain outside the workflow's own lab directory."""

    def lab(path: object) -> bool:
        return str(path).startswith(LAB_ROOT + "/") or str(path) == LAB_ROOT

    persistence = [
        f for f in (after.get("persistence") or {}).get("findings", []) if not lab(f["resource"])
    ]
    changes = (after.get("integrity") or {}).get("changes") or {}
    integrity = [p for paths in changes.values() for p in paths if not lab(p)]
    exposure = [
        f for f in (after.get("exposure") or {}).get("new_findings", []) if not lab(f["resource"])
    ]
    return {
        "persistence_changes": [f["resource"] for f in persistence],
        "integrity_changes": integrity,
        "new_exposure_findings": [f["resource"] for f in exposure],
        "new_listeners": [i["socket"] for i in (after.get("listeners") or {}).get("new", [])],
    }


def cleanup(
    run: Path,
    pre: Preflight,
    *,
    settings: Settings,
    timeout: int = 120,
    launcher: Launcher | None = None,
) -> dict[str, Any]:
    """Run the test's own cleanup (already approved by the caller), remove lab fixtures and
    verify the system outside the lab against the baselines taken before the test."""
    record = read_json(run / "record.json")
    if record is None or record.get("schema") != RECORD_SCHEMA:
        raise KeyError(str(run))
    if pre.test is None or pre.test.guid != record["test"]["guid"]:
        raise RunRefused("the cleanup preflight does not match the run's test")
    profile = pre.profile
    status, code, timed_out, traced = "NOT REQUIRED", 0, False, False
    if pre.cleanup.strip():
        if profile is not None and not profile.cleanup_safe:
            raise RunRefused(
                f"the reviewed profile marks this cleanup unsafe: {profile.cleanup_note}. "
                "Restore the affected files manually"
            )
        if launcher is None:
            if pre.environment.pwsh is None:
                raise RunRefused("pwsh not found")
            pwsh, test = pre.environment.pwsh, pre.test

            def launcher(_: Path) -> list[str]:
                return invoke_argv(
                    pwsh, Path(pre.environment.atomics), test, None, timeout, pre.overrides,
                    cleanup=True,
                )  # fmt: skip

        argv = launcher(run / "cleanup-log.csv")
        traced = pre.environment.tracing
        if traced:
            argv = tracing.strace_argv(run / "cleanup-trace.txt", argv)
        code, timed_out = launch(
            argv, private_dir(run / "workdir"), run / "cleanup-stdout.txt",
            run / "cleanup-stderr.txt", timeout + TIMEOUT_GRACE,
        )  # fmt: skip
        status = "COMPLETED" if code == 0 and not timed_out else "FAILED"
    removed = remove_fixtures(record.get("fixtures", []))
    return finish_cleanup(run, record, settings, profile, status, code, timed_out, traced, removed)


def finish_cleanup(
    run: Path,
    record: dict[str, Any],
    settings: Settings,
    profile: Profile | None,
    status: str,
    code: int,
    timed_out: bool,
    traced: bool,
    removed: list[str],
) -> dict[str, Any]:
    state = StateCollector(
        run_settings(settings, profile), run / "state", record["collection"]["integrity_paths"]
    )
    remaining = outside_lab(state.after("after-cleanup"))
    present = [p for p in (profile.cleanup_paths if profile else []) if os.path.lexists(p)]
    verified = status != "FAILED" and not present and not any(remaining.values())
    record["cleanup"].update(
        status=status,
        runner_exit_code=code,
        timed_out=timed_out,
        ran_at=datetime.now(UTC).isoformat(),
        traced=traced,
        fixtures_removed=removed,
        verification="PASS" if verified else "FAIL",
        verification_scope="system state outside the workflow's lab directory compared with "
        "the module baselines taken before the test",
        remaining_state_differences=remaining,
        paths_still_present=present,
    )
    write_private(run / "record.json", record)
    return dict(record["cleanup"])


def simulator_preflight(
    pre: Preflight, lab: Path, files: int, delay: float, profiles: dict[str, Profile]
) -> Preflight:
    """The dedicated ransomware simulator presented as a run of the same workflow.

    It is NOT an Atomic test: the Linux T1486 atomics encrypt a single file (and two of
    them do not run as written), so they cannot exercise a mass-modification detector.
    """
    command = (
        f"{sys.executable} -m runtime_engine.security.ransomware_sim {lab} "
        f"--files {files} --delay {delay}"
    )
    pre.test = AtomicTest(
        technique="T1486",
        technique_name="Data Encrypted for Impact (simulated)",
        number=0,
        name="Safe ransomware behaviour simulator (not an Atomic test)",
        guid=SIMULATOR_GUID,
        description="Creates dummy files in its own lab directory under the temp directory, "
        "rewrites them with random bytes and renames them to .locked.",
        platforms=["linux"],
        executor="python",
        elevation_required=False,
        command=command,
        cleanup=f"ransomware_sim.cleanup({lab})",
        dependencies=[],
        input_arguments={},
    )
    pre.profile = profiles.get(SIMULATOR_GUID)
    pre.command, pre.cleanup = command, pre.test.cleanup
    pre.risk, pre.risk_source = "A", "dedicated simulator: only files it creates in its own lab"
    pre.refusals = [r for r in pre.refusals if r.startswith("running as root")]
    pre.review_flags, pre.warnings = [], []
    if pre.profile is None:
        pre.warnings.append("no profile 'simulator-ransomware': the run will be INCONCLUSIVE")
    return pre


def cleanup_simulator(
    run: Path, settings: Settings, profiles: dict[str, Profile]
) -> dict[str, Any]:
    from runtime_engine.security import ransomware_sim

    record = read_json(run / "record.json")
    if record is None or record["test"]["guid"] != SIMULATOR_GUID:
        raise KeyError(str(run))
    lab = Path(record["simulator"]["lab"])
    removed = ransomware_sim.cleanup(lab) if lab.exists() else 0
    record["cleanup"]["simulator_files_removed"] = removed
    status = "COMPLETED" if not lab.exists() else "FAILED"
    return finish_cleanup(
        run, record, settings, profiles.get(SIMULATOR_GUID), status, 0, False, False, []
    )


def import_legacy(old: Path, engine_db: Path, results: Path = DEFAULT_RESULTS) -> Path:
    """Convert a run of the earlier monitor-based lab into an offline-analyzable run.

    Events are the ones the live monitor stored in `engine_db` during the run window that
    descend from the recorded runner identity; nothing is re-executed.
    """
    legacy = read_json(old / "record.json")
    if legacy is None or "runner" not in legacy:
        raise KeyError(str(old))
    start = datetime.fromisoformat(legacy["start_utc"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(legacy["end_utc"].replace("Z", "+00:00"))
    poll = float(legacy.get("engine", {}).get("poll_interval_seconds") or 2.0)
    connection = sqlite3.connect(f"file:{engine_db}?mode=ro", uri=True)
    try:
        rows = connection.execute("SELECT body FROM events").fetchall()
    finally:
        connection.close()
    stored = [Event.model_validate_json(row[0]) for row in rows]
    by_key = {e.process_key: e for e in stored if e.process_key}
    runner = legacy["runner"]["key"]
    lower, upper = start - timedelta(seconds=1), end + timedelta(seconds=poll + 2)
    selected: list[dict[str, Any]] = []
    for event in sorted(stored, key=lambda e: e.timestamp):
        if not lower <= event.timestamp <= upper or event.process_key == runner:
            continue
        current: Event | None = event
        for _ in range(12):
            parent = (
                json.dumps([current.host_id, current.ppid, current.parent_start_time],
                           separators=(",", ":"))
                if current and current.ppid and current.parent_start_time else None
            )  # fmt: skip
            if parent is None:
                break
            if parent == runner:
                selected.append(event.model_dump(mode="json"))
                break
            current = by_key.get(parent)
    if runner in by_key:
        context = by_key[runner].model_dump(mode="json")
        context["metadata"] = context["metadata"] | {
            "role": "atomic-runner (context, not part of the test)"
        }
        selected.insert(0, context)
    run_id = f"legacy-{legacy['run_id']}"
    run = private_dir(private_dir(results) / run_id)
    tracing.write_jsonl(selected, run / "events.jsonl")
    for name, target in (("test-output.txt", "stdout.txt"), ("execution-log.csv", None)):
        if (old / name).is_file():
            shutil.copyfile(old / name, run / (target or name))
            os.chmod(run / (target or name), 0o600)
    execution = legacy.get("execution", {})
    record = {
        "schema": RECORD_SCHEMA,
        "run_id": run_id,
        "created_at": start.isoformat(),
        "imported_from": str(old),
        "test": {
            "technique": legacy["technique"],
            "technique_name": legacy.get("technique_name", ""),
            "number": legacy["test_number"],
            "name": legacy["test_name"],
            "guid": legacy["guid"],
            "executor": legacy.get("executor"),
            "elevation_required": legacy.get("elevation_required", False),
            "risk": str(legacy.get("risk_class", "?"))[:1],
            "risk_source": "earlier lab triage",
            "overrides": {},
            "command": legacy.get("command", ""),
            "cleanup": legacy.get("cleanup", {}).get("command", ""),
            "prerequisites": 0,
            "profile": True,
        },
        "environment": {"atomics_commit": legacy.get("atomics_commit"),
                        "module_version": legacy.get("module_version")},
        "execution": {
            "status": execution.get("status", "UNKNOWN"),
            "exit_code": execution.get("exit_code"),
            "executor_pid": execution.get("executor_pid"),
            "start_utc": start.isoformat(),
            "end_utc": end.isoformat(),
            "duration_seconds": round((end - start).total_seconds(), 3),
            "stdout": "stdout.txt",
            "live_monitor_used": True,
        },
        "collection": {
            "collector": "proc-poll",
            "events_file": "events.jsonl",
            "events": len(selected),
            "source": f"live monitor database {engine_db} (poll interval {poll:g} s)",
            "integrity_paths": [],
            "ransomware_watch": [],
            "readability": {},
            "unavailable": UNAVAILABLE_ALWAYS + [
                f"imported run: /proc polling every {poll:g} s by the live monitor; processes "
                "shorter than that were missed",
                "no file, network or privilege events and no before/after module scans",
            ],
        },
        "cleanup": legacy.get("cleanup", {}),
    }  # fmt: skip
    write_private(run / "record.json", record)
    return run


def find_run(results: Path, run_id: str) -> Path:
    """Exact run ID or a unique prefix of one."""
    if "/" in run_id or run_id in ("", ".", ".."):
        raise KeyError(run_id)
    exact = results / run_id
    if (exact / "record.json").is_file():
        return exact
    matches = [p for p in results.glob(run_id + "*") if (p / "record.json").is_file()]
    if len(matches) == 1:
        return matches[0]
    raise KeyError(run_id)


def list_runs(results: Path) -> list[dict[str, Any]]:
    runs = []
    for path in sorted(results.glob("*/record.json")):
        record = read_json(path) or {}
        evaluation = read_json(path.parent / "evaluation.json")
        if record.get("schema") == RECORD_SCHEMA:
            test = record["test"]
            runs.append(
                {
                    "run_id": record["run_id"],
                    "kind": "imported" if record.get("imported_from") else "offline",
                    "created_at": record.get("created_at"),
                    "technique": test["technique"],
                    "number": test["number"],
                    "name": test["name"],
                    "execution": record["execution"]["status"],
                    "collector": record["collection"]["collector"],
                    "result": evaluation["result"] if evaluation else "NOT ANALYZED",
                    "cleanup": record.get("cleanup", {}).get("status"),
                    "path": str(path.parent),
                }
            )
        elif "runner" in record:
            runs.append(
                {
                    "run_id": record.get("run_id"),
                    "kind": "legacy (monitor-based; import to analyze offline)",
                    "created_at": record.get("start_utc"),
                    "technique": record.get("technique"),
                    "number": record.get("test_number"),
                    "name": record.get("test_name"),
                    "execution": record.get("execution", {}).get("status"),
                    "collector": "live monitor",
                    "result": (read_json(path.parent / "report.json") or {}).get("result", "?"),
                    "cleanup": record.get("cleanup", {}).get("status"),
                    "path": str(path.parent),
                }
            )
    return sorted(runs, key=lambda r: str(r["created_at"]))
