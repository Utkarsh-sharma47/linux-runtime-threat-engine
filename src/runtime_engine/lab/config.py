"""Generate a monitor YAML that points security modules at the isolated lab tree."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from runtime_engine.lab.paths import ransomware_lab_path, session_dirs


def lab_monitor_settings(session: Path, *, ransomware_dir: Path | None = None) -> dict[str, Any]:
    dirs = session_dirs(session)
    ransom = ransomware_dir or ransomware_lab_path(session.name)
    return {
        "database": str(session / "monitor.db"),
        "poll_interval_seconds": 1.0,
        "correlation_window_seconds": 180,
        "include_cmdline": True,
        "dashboard_refresh_seconds": 1.0,
        "reports_directory": str(dirs["reports"]),
        "security": {
            "promote_min_severity": "MEDIUM",
            "persistence": {
                "enabled": True,
                "interval_seconds": 8,
                # Lab-only locations — never real /etc persistence.
                "systemd_paths": [str(dirs["systemd"])],
                "cron_paths": [str(dirs["cron"])],
                "ssh_paths": [],
                "sudoers_paths": [],
                "privileged_dirs": [str(dirs["privileged"])],
                "sensitive_exec_dirs": [str(dirs["bin"]), str(dirs["privileged"])],
            },
            "network": {
                "enabled": True,
                "interval_seconds": 2,
                "include_loopback": True,
                "emit_events": True,
                "beacon_min_connections": 4,
                "beacon_cv_threshold": 0.35,
                "beacon_min_interval_seconds": 1,
            },
            "anomaly": {
                "enabled": True,
                "interval_seconds": 15,
                "model_directory": str(dirs["models"]),
                "min_training_rows": 50,
            },
            "integrity": {
                "enabled": True,
                "interval_seconds": 8,
                "paths": [str(dirs["integrity"])],
                "max_depth": 4,
                "max_files": 500,
            },
            "exposure": {
                "enabled": True,
                "interval_seconds": 12,
                "suid_paths": [str(dirs["privileged"]), str(dirs["exposure"])],
                "suid_max_depth": 2,
                "expected_suid": [],  # any SUID in the lab is unexpected by design
                "expected_listen_ports": [22, 53, 631, 8765],
                # Do not scan the real laptop's listeners, /tmp apps, sudoers, or PATH.
                # Lab SUID findings still come from privileged_files on lab paths above.
                "scan_services": False,
                "scan_processes": False,
                "scan_sudo": False,
                "scan_sensitive": False,
                "scan_path_dirs": False,
            },
            "ransomware": {
                "enabled": True,
                "interval_seconds": 1,
                "directories": [str(ransom)],
                "modification_threshold": 10,
                "rename_threshold": 5,
                "files_threshold": 8,
                "alert_score": 40,
                "min_indicators": 2,
            },
        },
    }


def write_monitor_config(session: Path, path: Path, *, ransomware_dir: Path | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = lab_monitor_settings(session, ransomware_dir=ransomware_dir)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    path.chmod(0o600)
    return path


__all__ = ["lab_monitor_settings", "write_monitor_config"]
