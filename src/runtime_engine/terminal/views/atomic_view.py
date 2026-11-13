"""Offline Atomic Red Team evaluation: inspection, per-run report, run list and summary."""

import json
from collections import Counter
from typing import Any

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from runtime_engine.atomic.analysis import LABELS
from runtime_engine.terminal.formatting import clean, severity_text, timestamp

GRADE_STYLES = {
    "DETECTED": "bold green",
    "PARTIALLY DETECTED": "bold yellow",
    "NOT DETECTED": "bold red",
    "INCONCLUSIVE": "bold magenta",
    "EXECUTION FAILED": "bold white on dark_red",
    "NOT APPLICABLE": "dim",
    "NOT ANALYZED": "dim",
}
EXECUTION_STYLES = {"COMPLETED": "bold green", "FAILED": "bold red", "TIMEOUT": "bold red"}
RISK_STYLES = {"A": "bold green", "B": "bold yellow", "C": "bold red"}
GRADES = ("DETECTED", "PARTIALLY DETECTED", "NOT DETECTED", "INCONCLUSIVE", "EXECUTION FAILED")


def grade(value: str | None) -> Text:
    return Text(value or "?", style=GRADE_STYLES.get(value or "", "bold"))


def grid() -> Table:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold", no_wrap=True)
    table.add_column(overflow="fold")
    return table


def block(title: str, body: RenderableType, style: str = "cyan") -> Panel:
    return Panel(body, title=title, title_align="left", border_style=style)


def code(text: str) -> Text:
    return Text(text.rstrip() or "(none)", style="bold" if text.strip() else "dim")


# ----- inspect -----


def render_inspect(pre: dict[str, Any]) -> RenderableType:
    env, test = pre["environment"], pre["test"]
    checks = grid()
    checks.add_row("ATOMICS", f"{env['atomics']} (commit {str(env['atomics_commit'])[:12]})")
    checks.add_row("PWSH / MODULE", f"{env['pwsh'] or 'MISSING'} / "
                   f"Invoke-AtomicRedTeam {env['module_version'] or 'MISSING'}")  # fmt: skip
    trace = (
        f"strace {env['strace']} (ptrace_scope={env['ptrace_scope']}): process tree, files, "
        "connections captured during execution"
        if env["tracing"]
        else "UNAVAILABLE: /proc polling fallback only"
    )
    checks.add_row("TELEMETRY", trace)
    checks.add_row("VIRTUALIZATION", env["virtualization"])
    checks.add_row(
        "USER", "root (refused)" if env["uid"] == 0 else f"uid {env['uid']} (normal user)"
    )
    parts: list[RenderableType] = [block("INSTALLATION", checks)]
    if test is not None:
        meta = grid()
        meta.add_row("TECHNIQUE", f"{test['technique']} {clean(test['technique_name'])}")
        meta.add_row("MITRE", test["mitre_url"])
        meta.add_row("TEST", f"#{test['number']} {clean(test['name'])}")
        meta.add_row("GUID", test["guid"])
        meta.add_row("DESCRIPTION", clean(test["description"], 600))
        who = "root (elevation_required)" if test["elevation_required"] else "this user"
        meta.add_row("EXECUTOR", f"{test['executor']} as {who}")
        risk = Text(f"{pre['risk']} {pre['risk_label']}", style=RISK_STYLES.get(pre["risk"], ""))
        risk.append(f"  ({clean(pre['risk_source'])})", style="dim")
        meta.add_row("RISK", risk)
        meta.add_row("TRIAGE FLAGS", "; ".join(test["triage_reasons"]) or "none")
        if pre["overrides"]:
            meta.add_row("INPUT OVERRIDES", json.dumps(pre["overrides"]))
        prereq = Text()
        for dep in test["prerequisites"]:
            prereq.append(f"- {clean(dep.get('description', '')).strip()}\n")
            prereq.append(f"  check: {dep.get('prereq_command', '').strip()}\n", style="dim")
            prereq.append(f"  get:   {dep.get('get_prereq_command', '').strip()}\n", style="dim")
        meta.add_row("PREREQUISITES", prereq if test["prerequisites"] else Text("none"))
        parts += [
            block(f"ATOMIC TEST {test['technique']} #{test['number']}", meta),
            block("EXACT COMMAND (rendered with the inputs that will be used)",
                  code(pre["command"]), "blue"),
            block("CLEANUP COMMAND (never run automatically)", code(pre["cleanup"]), "blue"),
        ]  # fmt: skip
        profile = pre.get("profile")
        if profile:
            expect = grid()
            for name, item in (profile.get("modules") or {}).items():
                rules = ", ".join(item["rules"]) or "applies; no rule expected (coverage check)"
                expect.add_row(LABELS.get(name, name), rules)
            if not profile.get("modules"):
                expect.add_row(LABELS["rules"], ", ".join(profile["expected_rules"]) or "none")
            expect.add_row("KEY PROCESSES", ", ".join(profile["key_processes"]) or "-")
            expect.add_row(
                "CLEANUP REVIEW",
                "safe" if profile["cleanup_safe"] else f"UNSAFE: {profile['cleanup_note']}",
            )
            if profile.get("fixtures"):
                expect.add_row(
                    "LAB FIXTURES",
                    "created by the workflow before the test, removed by atomic cleanup: "
                    + ", ".join(profile["fixtures"]),
                )
            if profile.get("module_paths"):
                expect.add_row("MODULE PATHS", json.dumps(profile["module_paths"]))
            expect.add_row("RATIONALE", clean(profile["rationale"], 800))
            parts.append(block("REVIEWED EXPECTATION PROFILE", expect, "green"))
    if pre["warnings"]:
        parts.append(
            block("WARNINGS", Text("\n".join(f"- {w}" for w in pre["warnings"])), "yellow")
        )
    if pre["refusals"]:
        refused = Text("\n".join(f"- {r}" for r in pre["refusals"]), style="bold red")
        parts.append(block("REFUSED: this test will not be executed", refused, "red"))
    elif test is not None:
        parts.append(
            Text(
                f"To execute exactly this test: atomic run {test['technique']} --test-number "
                f"{test['number']} --approve {pre['approval_token']}  (or type the token when "
                "prompted). The live monitor is not needed and is not started.",
                style="bold",
            )
        )
    return Group(*parts)


# ----- per-run report -----


def render_report(evaluation: dict[str, Any], record: dict[str, Any]) -> RenderableType:
    test, execution = evaluation["test"], evaluation["execution"]
    head = grid()
    head.add_row("RUN ID", evaluation["run_id"])
    head.add_row("TECHNIQUE", f"{test['technique']} {clean(test.get('technique_name', ''))}")
    head.add_row("TEST", f"#{test['number']} {clean(test['name'])}  ({test['guid']})")
    risk = Text(f"{test.get('risk', '?')}", style=RISK_STYLES.get(test.get("risk", ""), ""))
    risk.append(f"  {clean(test.get('risk_source', ''))}", style="dim")
    head.add_row("RISK", risk)
    if test.get("overrides"):
        head.add_row("INPUT OVERRIDES", json.dumps(test["overrides"]))
    status = execution.get("status", "?")
    line = Text(status, style=EXECUTION_STYLES.get(status, "bold"))
    if execution.get("exit_code") is not None:
        line.append(f"  exit code {execution['exit_code']}")
    if execution.get("duration_seconds") is not None:
        line.append(f"  {execution['duration_seconds']:.1f} s")
    if execution.get("executor_pid"):
        line.append(f"  executor PID {execution['executor_pid']}")
    head.add_row("EXECUTION", line)
    head.add_row("WINDOW", f"{timestamp(execution.get('start_utc'))} -> "
                 f"{timestamp(execution.get('end_utc'))}")  # fmt: skip
    head.add_row(
        "LIVE MONITOR",
        "used (imported run)" if execution.get("live_monitor_used") else "not used (offline)",
    )
    result = grade(evaluation["result"])
    head.add_row("OVERALL RESULT", result)
    head.add_row("WHY", Text("\n".join(evaluation["reasons"])))
    parts: list[RenderableType] = [
        Panel(
            head,
            title="ATOMIC RED TEAM - EDR EVALUATION (offline analysis)",
            title_align="left",
            border_style=GRADE_STYLES.get(evaluation["result"], "blue").replace("bold ", ""),
        )
    ]
    coverage = evaluation["coverage"]
    cov = Table(box=None, padding=(0, 2), show_header=True, expand=True)
    cov.add_column("CAPTURED DURING EXECUTION", ratio=1)
    cov.add_column("STATE DIFFERENCES (before vs after)", ratio=1)
    during, diff = coverage["captured_during_execution"], coverage["state_differences"]
    left = Text()
    left.append(f"collector: {coverage['collector']}\n", style="bold")
    for key, value in during.items():
        left.append(f"{key.replace('_', ' '):<20}{value:>6}\n")
    right = Text()
    right.append(f"telemetry types: {', '.join(coverage['telemetry_types_available']) or 'none'}\n",
                 style="bold")  # fmt: skip
    for key, value in diff.items():
        right.append(f"{key.replace('_', ' '):<24}{value:>6}\n")
    cov.add_row(left, right)
    parts.append(block("EVIDENCE COLLECTION", cov))
    results = Table(expand=True, title="DETECTION RESULTS BY COMPONENT", title_justify="left")
    results.add_column("COMPONENT", no_wrap=True)
    results.add_column("RESULT", no_wrap=True)
    results.add_column("EXPECTED", overflow="fold")
    results.add_column("OBSERVED", overflow="fold")
    results.add_column("WHY", overflow="fold", ratio=3)
    for item in evaluation["components"]:
        expected = item["expected"]
        results.add_row(
            item["label"],
            grade(item["grade"]),
            "-" if expected is None else (", ".join(expected) or "(behaviour only)"),
            ", ".join(item["observed"]) or "-",
            "; ".join(item["reasons"]),
        )
    parts.append(results)
    detections = evaluation["detections"]
    if detections:
        table = Table(expand=True, title="MATCHING DETECTIONS", title_justify="left")
        for column in ("RULE", "SEVERITY", "PROCESS", "EVENT", "RESOURCE", "INCIDENT"):
            table.add_column(column, overflow="fold")
        for item in detections[:20]:
            table.add_row(
                f"{item['rule_id']} {clean(item['rule_name'], 40)}",
                severity_text(item["severity"]),
                clean(item["process"]),
                item["event_type"],
                clean(item["resource"], 80),
                item["incident_id"],
            )
        parts.append(table)
    else:
        parts.append(Text("MATCHING DETECTIONS: none from the rule engine", style="dim"))
    if evaluation["incidents"]:
        inc = grid()
        for item in evaluation["incidents"]:
            inc.add_row(
                item["incident_id"],
                Text.assemble(severity_text(item["severity"]),
                              f"  rules {', '.join(item['rule_ids'])}, {item['alerts']} alert(s), "
                              f"{item['events']} event(s)"),
            )  # fmt: skip
        parts.append(block("INCIDENTS (offline correlation in analysis.db)", inc, "red"))
    processes = evaluation["processes"]
    if processes:
        table = Table(
            expand=True, title="PROCESS IDENTITY (test process tree)", title_justify="left"
        )
        for column in ("PID", "PROCESS", "LINEAGE", "COMMAND"):
            table.add_column(column, overflow="fold")
        for item in processes[:15]:
            table.add_row(
                str(item["pid"]),
                clean(item["process"]),
                clean(item["lineage"], 80),
                clean(" ".join(item.get("command_line") or []), 90),
            )
        if len(processes) > 15:
            table.caption = f"{len(processes) - 15} more in evaluation.json"
        parts.append(table)
    module_evidence = Text()
    for item in evaluation["components"]:
        if item["grade"] == "NOT APPLICABLE" or not item["evidence"]:
            continue
        module_evidence.append(f"{item['label']}\n", style="bold")
        for entry in item["evidence"][:6]:
            module_evidence.append(f"  - {clean(json.dumps(entry, default=str), 220)}\n")
    if module_evidence:
        parts.append(block("MODULE EVIDENCE", module_evidence))
    gaps = list(coverage["unavailable"])
    gaps += [f"{c['label']}: {g}" for c in evaluation["components"] for g in c["gaps"]
             if c["grade"] != "NOT APPLICABLE"]  # fmt: skip
    parts.append(block("EVIDENCE GAPS (not visible to this run)",
                       Text("\n".join(f"- {g}" for g in gaps) or "none"), "yellow"))  # fmt: skip
    fp = evaluation["false_positive_observations"]
    if fp["unexpected_detections"] or fp["detections_on_runner_context"]:
        parts.append(block("POSSIBLE FALSE POSITIVES", Text(json.dumps(fp, indent=2)), "yellow"))
    cleanup = record.get("cleanup", {})
    clean_text = Text()
    clean_text.append(f"{cleanup.get('status', '?')}", style="bold")
    if cleanup.get("verification"):
        clean_text.append(f"  verification: {cleanup['verification']}")
    if cleanup.get("command"):
        clean_text.append(f"\ncommand: {cleanup['command'].strip()}")
    if cleanup.get("reviewed_safe") is False:
        clean_text.append(f"\nreviewed UNSAFE: {cleanup.get('note')}", style="bold red")
    if cleanup.get("status") == "NOT RUN":
        clean_text.append(
            f"\nnext: atomic cleanup --run-id {evaluation['run_id']} (shows the command, asks "
            "for approval, then verifies against the pre-run baselines)",
            style="dim",
        )
    if cleanup.get("remaining_state_differences"):
        clean_text.append(f"\nremaining: {json.dumps(cleanup['remaining_state_differences'])}")
    parts.append(block("CLEANUP", clean_text, "blue"))
    parts.append(
        Text(
            "A successful Atomic execution is never counted as a detection. Missing telemetry "
            "is reported as INCONCLUSIVE, never as NOT DETECTED.",
            style="dim",
        )
    )
    return Group(*parts)


# ----- runs and summary -----


def render_runs(runs: list[dict[str, Any]]) -> RenderableType:
    if not runs:
        return Text("No Atomic runs recorded in this results directory.", style="dim")
    table = Table(title="ATOMIC RUNS", title_justify="left", expand=True)
    for column in ("RUN ID", "TEST", "KIND", "COLLECTOR", "EXECUTION", "RESULT", "CLEANUP"):
        table.add_column(column, overflow="fold")
    for run in runs:
        table.add_row(
            run["run_id"],
            f"{run['technique']} #{run['number']} {clean(run['name'], 40)}",
            run["kind"],
            run["collector"],
            Text(str(run["execution"]), style=EXECUTION_STYLES.get(str(run["execution"]), "")),
            grade(run["result"]),
            str(run["cleanup"]),
        )
    return table


def summarize(evaluations: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts only; no accuracy percentage over a hand-picked set of tests."""
    executed = [e for e in evaluations if e["execution"].get("status") == "COMPLETED"]
    outcomes = Counter(e["result"] for e in evaluations)
    modules: dict[str, Counter[str]] = {}
    telemetry_gaps: Counter[str] = Counter()
    for evaluation in evaluations:
        for item in evaluation["components"]:
            modules.setdefault(item["label"], Counter())[item["grade"]] += 1
            if item["grade"] == "INCONCLUSIVE" and not item["telemetry"]:
                telemetry_gaps[item["label"]] += 1
    collectors = Counter(e["coverage"]["collector"] for e in evaluations)
    benign = [e for e in evaluations if (e.get("profile") or {}).get("benign")]
    unexpected = sum(
        len(e["false_positive_observations"]["unexpected_detections"]) for e in evaluations
    )
    return {
        "execution_coverage": {
            "attempted": len(evaluations),
            "executed_successfully": len(executed),
            "failed": sum(1 for e in evaluations if e["execution"].get("status") != "COMPLETED"),
        },
        "detection_outcomes": {g: outcomes.get(g, 0) for g in GRADES},
        "modules": {name: dict(counts) for name, counts in modules.items()},
        "telemetry_coverage": {
            "collectors": dict(collectors),
            "inconclusive_for_missing_telemetry": dict(telemetry_gaps),
        },
        "false_positive_observations": {
            "benign_profile_runs": len(benign),
            "benign_runs_with_detections": sum(1 for e in benign if e["detections"]),
            "unexpected_detections": unexpected,
            "precision": "not computed: needs an independent labelled benign workload",
        },
        "runs": [
            {
                "run_id": e["run_id"],
                "test": f"{e['test']['technique']} #{e['test']['number']}",
                "name": e["test"]["name"],
                "execution": e["execution"].get("status"),
                "result": e["result"],
                "collector": e["coverage"]["collector"],
            }
            for e in evaluations
        ],
        "note": "Tests were selected by hand for safety; counts describe this selection only "
        "and are not an accuracy or coverage percentage for the engine.",
    }


def render_summary(summary: dict[str, Any]) -> RenderableType:
    if not summary["runs"]:
        return Text("No analyzed Atomic runs yet (atomic run / atomic analyze).", style="dim")
    execution = summary["execution_coverage"]
    head = grid()
    head.add_row("EXECUTION COVERAGE", f"{execution['attempted']} attempted, "
                 f"{execution['executed_successfully']} executed successfully, "
                 f"{execution['failed']} failed")  # fmt: skip
    outcome = Text()
    for name, count in summary["detection_outcomes"].items():
        outcome.append(f"{name} ", style=GRADE_STYLES[name])
        outcome.append(f"{count}   ")
    head.add_row("DETECTION OUTCOMES", outcome)
    telemetry = summary["telemetry_coverage"]
    missing = telemetry["inconclusive_for_missing_telemetry"] or "none"
    head.add_row(
        "TELEMETRY COVERAGE",
        f"collectors {telemetry['collectors']}; inconclusive because telemetry was missing: "
        f"{missing}",
    )
    fp = summary["false_positive_observations"]
    head.add_row(
        "FALSE POSITIVES",
        f"{fp['benign_runs_with_detections']} of {fp['benign_profile_runs']} benign-profile "
        f"runs had detections; {fp['unexpected_detections']} unreviewed detections; "
        f"precision {fp['precision']}",
    )
    matrix = Table(title="MODULE-LEVEL RESULTS (number of runs)", title_justify="left", expand=True)
    matrix.add_column("COMPONENT")
    columns = (*GRADES[:4], "NOT APPLICABLE")
    for name in columns:
        matrix.add_column(name, justify="right")
    for name, counts in summary["modules"].items():
        matrix.add_row(name, *[str(counts.get(c, 0)) for c in columns])
    runs = Table(title="RUNS", title_justify="left", expand=True)
    for column in ("RUN ID", "TEST", "NAME", "EXECUTION", "RESULT", "COLLECTOR"):
        runs.add_column(column, overflow="fold")
    for item in summary["runs"]:
        state = str(item["execution"])
        runs.add_row(
            item["run_id"],
            item["test"],
            clean(item["name"], 40),
            Text(state, style=EXECUTION_STYLES.get(state, "")),
            grade(item["result"]),
            item["collector"],
        )
    return Group(
        Panel(head, title="ATOMIC RED TEAM - EVALUATION SUMMARY", title_align="left"),
        matrix,
        runs,
        Text(summary["note"], style="dim"),
    )
