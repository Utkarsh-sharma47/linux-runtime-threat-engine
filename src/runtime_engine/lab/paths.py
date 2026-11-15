"""Security-lab path isolation. Everything mutable lives under a dedicated temp root."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

LAB_PREFIX = "rte-security-lab"
RANSOMWARE_PREFIX = "rte-ransomware-lab"
ACTIVE_NAME = "active"
STATUS_NAME = "status.json"
MARKER_NAME = ".rte-security-lab"
ENV_STATUS = "RTE_LAB_STATUS"
ENV_ROOT = "RTE_LAB_ROOT"
ENV_DB = "RTE_LAB_DB"


class LabPathError(ValueError):
    pass


def temp_root() -> Path:
    return Path(os.path.realpath(tempfile.gettempdir()))


def lab_root() -> Path:
    """Parent directory for all security-lab sessions: <tmp>/rte-security-lab/."""
    root = temp_root() / LAB_PREFIX
    return Path(os.path.realpath(root))


def ensure_lab_root() -> Path:
    root = lab_root()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    marker = root / MARKER_NAME
    if not marker.exists():
        marker.write_text("RTE security demonstration lab root\n", encoding="utf-8")
        marker.chmod(0o600)
    return root


def validate_under_lab_root(path: Path) -> Path:
    """Refuse paths outside <tmp>/rte-security-lab/ (except the ransomware sibling lab)."""
    real = Path(os.path.realpath(path))
    root = ensure_lab_root()
    try:
        real.relative_to(root)
    except ValueError as exc:
        raise LabPathError(f"path escapes lab root {root}: {real}") from exc
    if real == root:
        raise LabPathError("refusing to operate on the lab root itself")
    return real


def ransomware_lab_path(session_id: str) -> Path:
    """Ransomware simulator requires <tmp>/rte-ransomware-lab* directly under temp."""
    name = f"{RANSOMWARE_PREFIX}-{session_id}"
    if not name.startswith(RANSOMWARE_PREFIX):
        raise LabPathError("invalid ransomware lab name")
    return temp_root() / name


def session_dirs(session: Path) -> dict[str, Path]:
    """Standard subdirectories for one simulation session."""
    return {
        "bin": session / "bin",
        "cron": session / "cron",
        "systemd": session / "systemd",
        "privileged": session / "privileged",
        "integrity": session / "integrity",
        "exposure": session / "exposure",
        "anomaly": session / "anomaly",
        "network": session / "network",
        "evidence": session / "evidence",
        "reports": session / "reports",
        "models": session / "models",
    }


def create_session_tree(session: Path) -> dict[str, Path]:
    ensure_lab_root()
    session.mkdir(mode=0o700, parents=True, exist_ok=True)
    validate_under_lab_root(session)
    (session / MARKER_NAME).write_text(
        "SYNTHETIC LAB FIXTURE root — not a real host persistence location\n",
        encoding="utf-8",
    )
    dirs = session_dirs(session)
    for path in dirs.values():
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return dirs


def active_session_link() -> Path:
    return lab_root() / ACTIVE_NAME


def resolve_active_session() -> Path | None:
    link = active_session_link()
    if not link.exists():
        return None
    target = Path(os.path.realpath(link))
    try:
        return validate_under_lab_root(target)
    except LabPathError:
        return None


def set_active_session(session: Path) -> None:
    session = validate_under_lab_root(session)
    link = active_session_link()
    if link.exists() or link.is_symlink():
        link.unlink()
    link.symlink_to(session)


def status_path(session: Path | None = None) -> Path:
    if session is None:
        env = os.environ.get(ENV_STATUS)
        if env:
            return Path(env)
        active = resolve_active_session()
        if active is None:
            raise LabPathError("no active lab session; start the monitor first")
        session = active
    return validate_under_lab_root(session) / STATUS_NAME


__all__ = [
    "ACTIVE_NAME",
    "ENV_DB",
    "ENV_ROOT",
    "ENV_STATUS",
    "LAB_PREFIX",
    "LabPathError",
    "MARKER_NAME",
    "RANSOMWARE_PREFIX",
    "STATUS_NAME",
    "active_session_link",
    "create_session_tree",
    "ensure_lab_root",
    "lab_root",
    "ransomware_lab_path",
    "resolve_active_session",
    "session_dirs",
    "set_active_session",
    "status_path",
    "temp_root",
    "validate_under_lab_root",
]
