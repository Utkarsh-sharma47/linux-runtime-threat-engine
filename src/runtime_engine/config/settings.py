"""Small, validated runtime configuration."""

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from runtime_engine.events.schema import Severity


class ModuleSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    interval_seconds: float = Field(default=60, ge=1, le=86400)
    allow: list[str] = Field(default_factory=list)  # "glob" or "RULE:glob" on the resource
    severity_overrides: dict[str, Severity] = Field(default_factory=dict)


class PersistenceSettings(ModuleSettings):
    """Persistence and privilege locations. `~` expands to the monitoring user's home."""

    systemd_paths: list[str] = Field(
        default_factory=lambda: [
            "/etc/systemd/system",
            "/etc/systemd/user",
            "~/.config/systemd/user",
            "/usr/lib/systemd/system",
        ]
    )
    cron_paths: list[str] = Field(
        default_factory=lambda: [
            "/etc/crontab",
            "/etc/anacrontab",
            "/etc/cron.d",
            "/etc/cron.hourly",
            "/etc/cron.daily",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
            "/var/spool/cron/crontabs",
        ]
    )
    ssh_paths: list[str] = Field(
        default_factory=lambda: [
            "~/.ssh/authorized_keys",
            "~/.ssh/authorized_keys2",
            "/root/.ssh/authorized_keys",
        ]
    )
    sudoers_paths: list[str] = Field(default_factory=lambda: ["/etc/sudoers", "/etc/sudoers.d"])
    privileged_dirs: list[str] = Field(
        default_factory=lambda: [
            "/usr/bin",
            "/usr/sbin",
            "/usr/local/bin",
            "/usr/local/sbin",
            "/usr/libexec",
            "/usr/lib/openssh",
            "/usr/lib/dbus-1.0",
        ]
    )
    sensitive_exec_dirs: list[str] = Field(
        default_factory=lambda: ["/usr/local/bin", "/usr/local/sbin", "~/.local/bin"]
    )
    max_hash_bytes: int = Field(default=1_048_576, ge=0)


class NetworkSettings(ModuleSettings):
    """Socket snapshots from /proc/net; see docs/security/NETWORK.md."""

    interval_seconds: float = Field(default=5, ge=1, le=3600)
    include_loopback: bool = False
    exclude_cidrs: list[str] = Field(default_factory=list)
    emit_events: bool = True  # newly observed connections become NETWORK_CONNECTION events
    history_per_flow: int = Field(default=50, ge=3, le=1000)
    max_tracked_flows: int = Field(default=5000, ge=10, le=100_000)
    beacon_min_connections: int = Field(default=6, ge=3)
    beacon_cv_threshold: float = Field(default=0.25, gt=0, le=2)
    beacon_min_interval_seconds: float = Field(default=10, ge=0)
    beacon_max_interval_seconds: float = Field(default=3600, gt=0)
    repeat_threshold: int = Field(default=30, ge=2)
    repeat_window_seconds: float = Field(default=600, gt=0)


class AnomalySettings(ModuleSettings):
    """Unsupervised process anomaly scoring; see docs/security/ANOMALY.md."""

    interval_seconds: float = Field(default=30, ge=5, le=86400)
    model_directory: str = "models/anomaly"
    algorithm: str = Field(default="auto", pattern="^(auto|iforest|robust)$")
    n_estimators: int = Field(default=200, ge=10, le=2000)
    random_state: int = 42
    threshold_quantile: float = Field(default=0.99, gt=0.5, lt=1)
    threshold_override: float | None = None
    min_training_rows: int = Field(default=50, ge=10)
    max_missing_fraction: float = Field(default=0.5, ge=0, le=1)
    deviation_z: float = Field(default=3.0, gt=0)
    exclude_names: list[str] = Field(default_factory=list)


class IntegritySettings(ModuleSettings):
    """Merkle-tree file integrity monitoring; see docs/security/INTEGRITY.md."""

    interval_seconds: float = Field(default=300, ge=5, le=86400)
    paths: list[str] = Field(
        default_factory=lambda: [
            "/etc/passwd",
            "/etc/group",
            "/etc/hosts",
            "/etc/ssh/sshd_config",
            "/etc/systemd/system",
            "/usr/local/bin",
            "/usr/local/sbin",
        ]
    )
    exclude: list[str] = Field(
        default_factory=lambda: ["*.swp", "*~", "*.tmp", "*.pid", "*.lock", "*.log", "*.cache"]
    )
    max_depth: int = Field(default=8, ge=1, le=64)
    max_files: int = Field(default=50_000, ge=1)
    max_file_bytes: int = Field(default=256 * 1024 * 1024, ge=0)


class ExposureSettings(ModuleSettings):
    """Attack surface and exposure analysis; see docs/security/EXPOSURE.md."""

    interval_seconds: float = Field(default=900, ge=10, le=86400)
    suid_paths: list[str] = Field(
        default_factory=lambda: [
            "/usr/bin",
            "/usr/sbin",
            "/usr/local/bin",
            "/usr/local/sbin",
            "/usr/lib",
            "/usr/libexec",
            "/opt",
        ]
    )
    suid_max_depth: int = Field(default=3, ge=1, le=16)
    full_scan_every: int = Field(default=4, ge=1)  # every Nth scan re-walks everything
    expected_suid: list[str] = Field(
        default_factory=lambda: [
            "passwd", "sudo", "su", "mount", "umount", "chsh", "chfn", "newgrp", "gpasswd",
            "pkexec", "fusermount", "fusermount3", "ssh-keysign", "dbus-daemon-launch-helper",
            "polkit-agent-helper-1", "unix_chkpwd", "pam_extrausers_chkpwd", "chage", "expiry",
            "crontab", "at", "Xorg.wrap", "snap-confine", "ntfs-3g", "pppd", "mount.nfs",
            "ssh-agent", "write", "wall", "bsd-write", "dotlockfile", "plocate", "utempter",
            "chrome-sandbox", "opera_sandbox", "camel-lock-helper-1.2", "w3mimgdisplay",
            "mtr-packet", "ping", "traceroute6.iputils", "arping", "clockdiff",
        ]
    )  # fmt: skip
    expected_listen_ports: list[int] = Field(default_factory=lambda: [22, 53, 631])
    weights: dict[str, float] = Field(
        default_factory=lambda: {"CRITICAL": 40.0, "HIGH": 15.0, "MEDIUM": 5.0, "LOW": 0.5}
    )


class RansomwareSettings(ModuleSettings):
    """Behavioural ransomware early warning; off until directories are configured."""

    enabled: bool = True
    interval_seconds: float = Field(default=2, ge=0.2, le=3600)
    directories: list[str] = Field(default_factory=list)  # nothing personal by default
    exclude: list[str] = Field(default_factory=lambda: ["*.swp", "*~", "*.tmp", ".git"])
    max_watches: int = Field(default=2000, ge=1)
    window_seconds: float = Field(default=30, gt=0)
    max_events_per_window: int = Field(default=20_000, ge=100)
    sample_bytes: int = Field(default=65536, ge=256, le=4 * 1024 * 1024)
    entropy_reads_per_second: float = Field(default=50, gt=0)
    high_entropy: float = Field(default=7.2, gt=0, le=8)
    low_entropy: float = Field(default=6.0, gt=0, le=8)
    modification_threshold: int = Field(default=30, ge=1)  # per window
    rename_threshold: int = Field(default=15, ge=1)
    files_threshold: int = Field(default=20, ge=1)
    directories_threshold: int = Field(default=3, ge=1)
    entropy_ratio_threshold: float = Field(default=0.5, gt=0, le=1)
    extension_ratio_threshold: float = Field(default=0.6, gt=0, le=1)
    alert_score: float = Field(default=50, gt=0, le=100)
    min_indicators: int = Field(default=2, ge=1)


class SecuritySettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    promote_min_severity: Severity = Severity.MEDIUM  # findings below stay out of incidents
    persistence: PersistenceSettings = Field(default_factory=PersistenceSettings)
    network: NetworkSettings = Field(default_factory=NetworkSettings)
    anomaly: AnomalySettings = Field(default_factory=AnomalySettings)
    integrity: IntegritySettings = Field(default_factory=IntegritySettings)
    exposure: ExposureSettings = Field(default_factory=ExposureSettings)
    ransomware: RansomwareSettings = Field(default_factory=RansomwareSettings)


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    database: str = "runtime.db"
    correlation_window_seconds: float = Field(default=120, gt=0, le=86400)
    poll_interval_seconds: float = Field(default=2, ge=0.1)
    include_cmdline: bool = False
    reports_directory: str = "reports/generated"
    event_queue_capacity: int = Field(default=10000, ge=1, le=1_000_000)
    dashboard_refresh_seconds: float = Field(default=1.0, ge=0.1, le=60)
    security: SecuritySettings = Field(default_factory=SecuritySettings)

    @classmethod
    def load(cls, path: Path | None) -> "Settings":
        if path is None:
            return cls()
        raw = yaml.safe_load(path.read_text())
        return cls.model_validate(raw)
