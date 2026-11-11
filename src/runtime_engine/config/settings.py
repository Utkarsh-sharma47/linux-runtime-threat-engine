"""Small, validated runtime configuration."""

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    database: str = "runtime.db"
    correlation_window_seconds: float = Field(default=120, gt=0, le=86400)
    poll_interval_seconds: float = Field(default=2, ge=0.1)
    include_cmdline: bool = False
    reports_directory: str = "reports/generated"
    event_queue_capacity: int = Field(default=10000, ge=1, le=1_000_000)
    dashboard_refresh_seconds: float = Field(default=1.0, ge=0.1, le=60)

    @classmethod
    def load(cls, path: Path | None) -> "Settings":
        if path is None:
            return cls()
        raw = yaml.safe_load(path.read_text())
        return cls.model_validate(raw)
