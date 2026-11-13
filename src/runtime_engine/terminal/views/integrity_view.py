"""File Integrity Monitor page: roots, verified files, changes, proofs, anchor status."""

from typing import Any

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from runtime_engine.security.findings import Finding, ScanReport
from runtime_engine.terminal.formatting import clean, timestamp
from runtime_engine.terminal.views.security_common import (
    as_dict,
    coverage_panel,
    findings_table,
    report_header,
)


def change_table(title: str, paths: list[str], style: str) -> RenderableType:
    if not paths:
        return Text(f"{title}: none", style="dim")
    table = Table(title=f"{title} ({len(paths)})", title_justify="left", show_header=False)
    table.add_column(overflow="fold")
    for path in paths[:25]:
        table.add_row(Text(clean(path), style=style))
    if len(paths) > 25:
        table.caption = f"{len(paths) - 25} more"
    return table


def integrity_status(summary: dict[str, Any]) -> Text:
    if not summary:
        return Text("NO VERIFICATION YET", style="bold yellow")
    if summary.get("root_matches"):
        return Text("INTACT: current root equals the baseline root", style="bold green")
    return Text("CHANGED: current root differs from the baseline root", style="bold red")


def render_integrity(
    report: ScanReport | None,
    findings: list[Finding] | list[dict[str, Any]],
    *,
    baseline: dict[str, Any] | None = None,
    anchor: dict[str, Any] | None = None,
    proof: dict[str, Any] | None = None,
) -> RenderableType:
    summary = report.summary if report else {}
    counts = summary.get("counts", {})
    changes = summary.get("changes", {})
    root = summary.get("baseline_root") or (baseline or {}).get("root")
    base = baseline or {}
    created = summary.get("baseline_created_at") or base.get("created_at")
    files = base.get("leaf_count", summary.get("baseline_files", "-"))
    header = report_header(
        "FILE INTEGRITY MONITOR",
        report,
        [
            ("INTEGRITY", integrity_status(summary)),
            ("BASELINE ROOT", clean(root or "no baseline (run: integrity baseline)")),
            ("CURRENT ROOT", clean(summary.get("current_root", "-"))),
            (
                "BASELINE",
                f"{files} files, created {timestamp(created)}",
            ),
            ("FILES VERIFIED", str(summary.get("files_verified", "-"))),
            (
                "CHANGES",
                ", ".join(f"{k.replace('_', ' ')} {v}" for k, v in counts.items()) or "-",
            ),
            (
                "MONITORED",
                clean(", ".join(summary.get("paths", (baseline or {}).get("paths", [])))),
            ),
        ],
    )
    parts: list[RenderableType] = [header, coverage_panel(report) if report else Text("")]
    parts += [
        change_table("MODIFIED (content)", changes.get("modified", []), "bold red"),
        change_table(
            "PERMISSIONS / OWNERSHIP CHANGED", changes.get("metadata_changed", []), "yellow"
        ),
        change_table("ADDED", changes.get("added", []), "cyan"),
        change_table("DELETED", changes.get("deleted", []), "magenta"),
    ]
    if anchor is not None:
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold")
        grid.add_column(overflow="fold")
        grid.add_row("ANCHORED ROOT", clean(anchor["anchored_root"]))
        grid.add_row("SIGNATURE", clean(anchor["signature"]))
        grid.add_row(
            "BASELINE VS ANCHOR",
            Text("matches", style="green")
            if anchor["baseline_matches_anchor"]
            else Text(
                "DIFFERENT: the stored baseline was replaced or the anchor is stale",
                style="bold red",
            ),
        )
        parts.append(Panel(grid, title="EXTERNAL ANCHOR", title_align="left"))
    if proof is not None:
        parts.append(render_proof(proof))
    parts.append(
        findings_table(
            [as_dict(f) for f in findings], "INTEGRITY FINDINGS", empty="No integrity findings."
        )
    )
    parts.append(
        Text(
            "A baseline stored on this host can be replaced by root; compare against an "
            "exported anchor kept elsewhere for tamper evidence.",
            style="dim italic",
        )
    )
    return Panel(
        Group(*parts), title="FILE INTEGRITY MONITOR", title_align="left", border_style="cyan"
    )


def render_proof(proof: dict[str, Any]) -> RenderableType:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", no_wrap=True)
    grid.add_column(overflow="fold")
    grid.add_row("FILE", clean(proof["path"]))
    grid.add_row("LEAF", proof["leaf"])
    grid.add_row("ROOT", proof["root"])
    grid.add_row(
        "VERIFIED",
        Text("yes: the leaf and siblings hash to the root", style="green")
        if proof["verified"]
        else Text("NO: the proof does not reach this root", style="bold red"),
    )
    if "matches_baseline_root" in proof:
        grid.add_row(
            "AGAINST BASELINE",
            Text("unchanged since baseline", style="green")
            if proof["matches_baseline_root"]
            else Text("does not verify against the baseline root", style="yellow"),
        )
    steps = Table(box=None, show_edge=False)
    steps.add_column("#")
    steps.add_column("SIBLING SIDE")
    steps.add_column("SIBLING HASH", overflow="fold")
    for index, step in enumerate(proof["proof"], 1):
        steps.add_row(str(index), step["side"], step["hash"])
    return Panel(Group(grid, steps), title="MERKLE MEMBERSHIP PROOF", title_align="left")
