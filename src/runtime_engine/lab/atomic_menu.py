"""Interactive menu of reviewed Atomic profiles (inspect → approve → optional run).

Uses the same offline Atomic workflow as `python -m runtime_engine.main atomic …`.
Does not claim offline evidence is live monitoring. For the synthetic live path use
`--live-accept` (no real Atomic attack).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from runtime_engine.atomic import analysis, preflight, runner
from runtime_engine.atomic.evidence import read_json
from runtime_engine.atomic.profiles import load_profiles
from runtime_engine.config.settings import Settings
from runtime_engine.detection.rule_loader import load_rules
from runtime_engine.terminal.views import atomic_view

# Reviewed profiles for workstation demos (technique, test number, note).
PROFILES: tuple[tuple[str, int, str, str], ...] = (
    ("T1059.004", 8, "A", "Shell loop (benign; expect NOT DETECTED)"),
    ("T1033", 2, "A", "User discovery (short-lived; often INCONCLUSIVE live)"),
    ("T1036.003", 2, "B", "Masquerading /tmp/crond (needs --allow-review-required)"),
    ("T1071.001", 3, "B", "HTTP curl; use domain=203.0.113.10 only"),
    ("T1222.002", 1, "B", "chmod SUID lab tool (lab fixture paths)"),
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Select and optionally run a reviewed Atomic test (approval-gated)"
    )
    parser.add_argument("--dry-run", action="store_true", help="Inspect only; do not execute")
    parser.add_argument(
        "--live-accept",
        action="store_true",
        help="Run synthetic live-accept demo (NOT a real Atomic attack)",
    )
    parser.add_argument(
        "--atomics",
        type=Path,
        default=preflight.DEFAULT_ATOMICS,
        help="Path to Atomic Red Team atomics folder",
    )
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=Path.home() / "AtomicRedTeam" / "lab-results",
        help="Where offline Atomic run evidence is written",
    )
    args = parser.parse_args(argv)
    console = Console()

    if args.live_accept:
        from runtime_engine.terminal import atomic_app

        ns = argparse.Namespace(
            action="live-accept",
            json=False,
            engine_db=Path("testing/reports/live-accept.db"),
            results_dir=args.results_dir,
            atomics=args.atomics,
            profiles=None,
        )
        return atomic_app.live_accept(ns, Settings(), load_rules(), console)

    table = Table(title="Reviewed Atomic profiles (approval required to execute)")
    table.add_column("#", justify="right")
    table.add_column("Technique")
    table.add_column("Test")
    table.add_column("Risk")
    table.add_column("Note")
    for index, (tech, num, risk, note) in enumerate(PROFILES, 1):
        table.add_row(str(index), tech, str(num), risk, note)
    console.print(table)
    console.print(
        "[dim]OFFLINE EVALUATION ≠ live monitor. "
        "Live TUI demos: ./scripts/security-lab/run-security-lab.sh scenarios "
        "or --live-accept (SYNTHETIC).[/dim]"
    )
    if not sys.stdin.isatty():
        print(
            "refused: interactive menu requires a TTY (or use --live-accept / --dry-run with "
            "scripted input)",
            file=sys.stderr,
        )
        return 2

    choice = console.input("Select # to inspect (blank to abort): ").strip()
    if not choice:
        return 0
    try:
        index = int(choice)
        tech, num, risk, _note = PROFILES[index - 1]
    except (ValueError, IndexError):
        print("invalid selection", file=sys.stderr)
        return 2

    profiles = load_profiles()
    env = preflight.environment(args.atomics)
    overrides: dict[str, str] = {}
    if tech == "T1071.001":
        overrides["domain"] = "203.0.113.10"
    pre = preflight.check(
        env,
        tech,
        num,
        profiles,
        overrides,
        allow_review_required=(risk == "B"),
        prereqs_reviewed=True,
    )
    console.print(atomic_view.render_inspect(pre.as_dict()))
    if pre.refusals or pre.test is None:
        print("refused: " + "; ".join(pre.refusals), file=sys.stderr)
        return 4
    if args.dry_run:
        console.print("DRY RUN: inspected only; nothing executed.")
        return 0

    token = console.input(
        f"Type '{pre.token}' to execute OFFLINE Atomic evaluation, anything else to abort: "
    ).strip()
    if token != pre.token:
        print("not approved: nothing was executed", file=sys.stderr)
        return 5

    run = runner.execute(pre, settings=Settings(), results=args.results_dir)
    evaluation = analysis.analyze(run, load_rules(), Settings(), profiles)
    record = read_json(run / "record.json") or {}
    console.print(atomic_view.render_report(evaluation, record))
    console.print(f"[green]run dir:[/green] {run}")
    console.print(
        "[yellow]Provenance: ATOMIC EXECUTION EVIDENCE (offline). "
        "Not live dashboard telemetry.[/yellow]"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
