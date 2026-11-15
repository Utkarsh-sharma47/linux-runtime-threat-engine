"""Scenario B: shell → curl against a local lab HTTP server (loopback)."""

from __future__ import annotations

import shutil
import subprocess
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from runtime_engine.lab.paths import session_dirs
from runtime_engine.lab.status import LabStatus, ScenarioResult, now_iso


def _handler(directory: str) -> type[SimpleHTTPRequestHandler]:
    class QuietHandler(SimpleHTTPRequestHandler):
        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(*args, directory=directory, **kwargs)  # type: ignore[arg-type]

        def log_message(self, format: str, *args: object) -> None:  # noqa: A003
            return

    return QuietHandler


def run(session: Path, status: LabStatus, dry_run: bool) -> ScenarioResult:
    dirs = session_dirs(session)
    port = 8765
    url = f"http://127.0.0.1:{port}/"
    result = ScenarioResult(
        name="network",
        status="dry-run" if dry_run else "running",
        started_at=now_iso(),
        provenance=["REAL_HOST_TELEMETRY"],
        behavior=[
            "Start a local HTTP server bound to 127.0.0.1 inside the lab network dir",
            "Launch curl from a shell several times (process + connection attribution)",
            "Leave activity visible for NetworkMonitor snapshot polling",
        ],
        collectors=["ProcCollector", "NetworkMonitor (/proc/net snapshots)"],
        expected_rules=["RT005"],
        expected_modules=["network"],
        notes=[
            "Uses loopback only. Lab monitor config sets include_loopback: true.",
            "RT006 (203.0.113.10 watchlist) is not used here.",
            "Dashboard: n (network investigation), p, r, i.",
            "Short-lived connections may be missed between network module scans.",
        ],
        grade_hint="expect RT005 (shell→curl); network events if a snapshot catches them",
        evidence={"url": url, "port": port, "docroot": str(dirs["network"])},
    )
    if dry_run:
        result.status = "dry-run"
        result.ended_at = now_iso()
        return result

    (dirs["network"] / "index.html").write_text(
        "<html><body>RTE security lab (loopback only)</body></html>\n", encoding="utf-8"
    )
    curl = shutil.which("curl")
    if curl is None:
        result.status = "failed"
        result.notes.append("curl not found on PATH")
        result.ended_at = now_iso()
        return result

    server = ThreadingHTTPServer(("127.0.0.1", port), _handler(str(dirs["network"])))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    codes: list[int] = []
    try:
        for _ in range(5):
            proc = subprocess.run(  # noqa: S603
                ["bash", "-c", f"curl -s --connect-timeout 2 --max-time 3 {url} >/dev/null"],
                check=False,
                timeout=10,
            )
            codes.append(proc.returncode)
            time.sleep(0.8)
        status.active_connections = [f"127.0.0.1:{port} (lab HTTP)"]
        time.sleep(3.0)
    finally:
        server.shutdown()
        server.server_close()
    result.evidence["curl_exit_codes"] = codes
    result.status = "completed"
    result.ended_at = now_iso()
    return result
