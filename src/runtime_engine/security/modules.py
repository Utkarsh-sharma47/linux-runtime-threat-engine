"""Build the enabled security modules from settings and persisted baselines."""

from runtime_engine.config.settings import ModuleSettings, Settings
from runtime_engine.security.findings import SeverityPolicy
from runtime_engine.security.network import NetworkMonitor
from runtime_engine.security.persistence import PersistenceMonitor, entries_from_body
from runtime_engine.security.scheduler import SecurityModule
from runtime_engine.storage.database import Database


def policy(settings: Settings, module: ModuleSettings) -> SeverityPolicy:
    return SeverityPolicy(
        settings.security.promote_min_severity, module.severity_overrides, module.allow
    )


def persistence_monitor(settings: Settings, database: Database) -> PersistenceMonitor:
    config = settings.security.persistence
    body = database.baseline("persistence")
    if body is None:
        return PersistenceMonitor(config, policy(settings, config))
    return PersistenceMonitor(
        config,
        policy(settings, config),
        entries_from_body(body),
        f"persisted baseline from {body.get('created_at', '?')}",
    )


def build_modules(
    settings: Settings, database: Database
) -> tuple[list[SecurityModule], dict[str, str]]:
    """Returns (enabled modules, status for every module that is not running)."""
    modules: list[SecurityModule] = []
    off: dict[str, str] = {}
    if settings.security.persistence.enabled:
        modules.append(persistence_monitor(settings, database))
    else:
        off["persistence"] = "disabled in configuration"
    network = settings.security.network
    if network.enabled:
        modules.append(NetworkMonitor(network, policy(settings, network)))
    else:
        off["network"] = "disabled in configuration"
    return modules, off
