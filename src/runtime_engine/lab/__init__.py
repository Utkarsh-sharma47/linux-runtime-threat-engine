"""One-command security demonstration lab for the live EDR dashboard."""

from runtime_engine.lab.orchestrator import main as run_lab_main
from runtime_engine.lab.session import prepare_session

__all__ = ["prepare_session", "run_lab_main"]
