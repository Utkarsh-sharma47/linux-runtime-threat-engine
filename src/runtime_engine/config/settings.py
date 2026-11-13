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


class SecuritySettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    promote_min_severity: Severity = Severity.MEDIUM  # findings below stay out of incidents
    persistence: PersistenceSettings = Field(default_factory=PersistenceSettings)


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
