"""Anomaly Detector page: model status, training data, ranking, deviations, threshold."""

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


def model_panel(model: dict[str, Any] | None) -> RenderableType:
    if not model:
        return Panel(
            Text(
                "No trained model. Train one on a reviewed baseline (anomaly train) or try "
                "the synthetic demonstration (anomaly demo). Nothing is scored until then.",
                style="yellow",
            ),
            title="MODEL",
            title_align="left",
        )
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", no_wrap=True)
    grid.add_column(overflow="fold")
    grid.add_row("VERSION", clean(model.get("version")))
    grid.add_row("ALGORITHM", clean(model.get("algorithm")))
    grid.add_row("TRAINED", timestamp(model.get("trained_at")))
    grid.add_row(
        "TRAINING DATA",
        f"{model.get('training_rows')} rows from {clean(model.get('dataset'))} "
        f"({model.get('excluded_rows')} excluded: labelled anomalous or tied to incidents)",
    )
    grid.add_row("BASELINE", clean(model.get("baseline_assertion")))
    grid.add_row("FEATURES", ", ".join(model.get("features", [])))
    if model.get("dropped_features"):
        grid.add_row(
            "DROPPED",
            ", ".join(model["dropped_features"]) + " (missing in too many training rows)",
        )
    grid.add_row(
        "THRESHOLD",
        f"{float(model.get('threshold', 0)):.4f} ({clean(model.get('threshold_rule'))})",
    )
    return Panel(grid, title="MODEL", title_align="left")


def ranking_table(
    ranking: list[dict[str, Any]], threshold: float | None, limit: int = 15
) -> RenderableType:
    if not ranking:
        return Text("No processes scored.", style="dim")
    table = Table(
        title="PROCESS ANOMALY RANKING (score is relative rarity, not a malware probability)",
        title_justify="left",
        expand=True,
    )
    for column in (
        "#",
        "PROCESS",
        "PID",
        "SCORE",
        "THRESHOLD",
        "FEATURE DEVIATIONS (|z| vs training)",
    ):
        table.add_column(column, no_wrap=column != "FEATURE DEVIATIONS (|z| vs training)")
    for index, item in enumerate(ranking[:limit], 1):
        above = item["above_threshold"]
        deviations = ", ".join(
            f"{d['feature']} {d['direction']} "
            f"(z={d['z']:+.1f}, {d['value']:.4g} vs {d['training_median']:.4g})"
            for d in item["deviations"][:3]
            if d["value"] is not None
        )
        table.add_row(
            str(index),
            clean(item["process"], 20),
            str(item["pid"]),
            f"{item['score']:.4f}",
            Text("ABOVE", style="bold yellow") if above else Text("below", style="dim"),
            clean(deviations) or "none beyond the deviation limit",
        )
    if threshold is not None:
        table.caption = (
            f"threshold {threshold:.4f}; deviations are computed separately from the score"
        )
    return table


def render_anomaly(
    report: ScanReport | None,
    findings: list[Finding] | list[dict[str, Any]],
    *,
    model: dict[str, Any] | None = None,
    ranking: list[dict[str, Any]] | None = None,
    sampled: int | None = None,
) -> RenderableType:
    summary = report.summary if report else {}
    model = model if model is not None else summary.get("model")
    ranking = ranking if ranking is not None else summary.get("ranking", [])
    threshold = float(model["threshold"]) if model else None
    header = report_header(
        "ANOMALY DETECTOR",
        report,
        [
            ("SCORED", f"{summary.get('processes_sampled', sampled or len(ranking))} row(s)"),
            (
                "ABOVE THRESHOLD",
                str(summary.get("above_threshold", sum(r["above_threshold"] for r in ranking))),
            ),
        ],
    )
    rows = [as_dict(f) for f in findings]
    return Panel(
        Group(
            header,
            model_panel(model),
            coverage_panel(report) if report else Text(""),
            ranking_table(ranking, threshold),
            findings_table(
                rows,
                "BEHAVIOURAL FINDINGS (AN001)",
                empty="No process scored above the threshold.",
            )
            if report is not None
            else Text(
                "Ranking only: this is not a monitoring scan, so no findings were recorded.",
                style="dim",
            ),
            Text(
                "Anomalies are leads for review: unusual is not malicious, and deterministic "
                "rules do not depend on this model.",
                style="dim italic",
            ),
        ),
        title="ANOMALY DETECTOR",
        title_align="left",
        border_style="cyan",
    )
