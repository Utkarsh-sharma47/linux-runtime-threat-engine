"""Create and register a security-lab simulation session."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from runtime_engine.lab.config import write_monitor_config
from runtime_engine.lab.paths import (
    ENV_DB,
    ENV_ROOT,
    ENV_STATUS,
    create_session_tree,
    ensure_lab_root,
    lab_root,
    ransomware_lab_path,
    set_active_session,
    status_path,
)
from runtime_engine.lab.status import LabStatus, now_iso, write_status
from runtime_engine.security import ransomware_sim


def new_session_id() -> str:
    return datetime.now(UTC).strftime("lab-%Y%m%dT%H%M%SZ")


def prepare_session(
    session_id: str | None = None,
    *,
    repo_root: Path | None = None,
) -> tuple[Path, Path, Path, LabStatus]:
    """Create lab tree, ransomware sibling, monitor config, and initial status."""
    ensure_lab_root()
    sid = session_id or new_session_id()
    session = lab_root() / sid
    create_session_tree(session)
    ransom = ransomware_lab_path(sid)
    ransomware_sim.create_lab(str(ransom))
    config = write_monitor_config(session, session / "monitor.yaml", ransomware_dir=ransom)
    set_active_session(session)
    status = LabStatus(
        session_id=sid,
        lab_dir=str(session),
        database=str(session / "monitor.db"),
        started_at=now_iso(),
        updated_at=now_iso(),
        phase="idle",
        message="Lab session prepared. Start the monitor, then run scenarios.",
        collector_health={
            "proc": "pending (start monitor)",
            "security_modules": "pending (start monitor)",
        },
    )
    write_status(status, status_path(session))
    # Convenience pointer for operators (plain text — never an absolute symlink in-tree;
    # absolute symlinks break `python -m build` / sdist packaging).
    if repo_root is not None:
        cfg_dir = repo_root / "scripts" / "security-lab" / "config"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        for name in ("active-monitor.yaml", "active-monitor.path"):
            stale = cfg_dir / name
            if stale.exists() or stale.is_symlink():
                stale.unlink()
        (cfg_dir / "active-monitor.path").write_text(str(config) + "\n", encoding="utf-8")
    return session, config, ransom, status


def env_exports(session: Path, config: Path) -> dict[str, str]:
    return {
        ENV_ROOT: str(session),
        ENV_STATUS: str(status_path(session)),
        ENV_DB: str(session / "monitor.db"),
        "RTE_LAB_CONFIG": str(config),
    }


__all__ = ["env_exports", "new_session_id", "prepare_session"]
