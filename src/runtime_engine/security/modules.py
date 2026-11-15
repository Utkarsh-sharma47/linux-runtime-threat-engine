"""Build the enabled security modules from settings and persisted baselines."""

from runtime_engine.config.settings import ModuleSettings, Settings
from runtime_engine.security.anomaly import AnomalyDetector
from runtime_engine.security.exposure import ExposureAnalyzer
from runtime_engine.security.findings import SecurityState, SeverityPolicy
from runtime_engine.security.integrity import IntegrityMonitor
from runtime_engine.security.network import NetworkMonitor
from runtime_engine.security.persistence import PersistenceMonitor, entries_from_body
from runtime_engine.security.ransomware import RansomwareMonitor
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
    settings: Settings, database: Database, security: SecurityState | None = None
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
    anomaly = settings.security.anomaly
    if anomaly.enabled:

        def resources() -> dict[str, dict[str, int]] | None:
            # Reuse the network module's descriptor scan instead of enumerating /proc again.
            report = security.report("network") if security is not None else None
            if report is None:
                return None
            value: dict[str, dict[str, int]] | None = report.summary.get("process_resources")
            return value

        modules.append(AnomalyDetector(anomaly, policy(settings, anomaly), resources))
    else:
        off["anomaly"] = "disabled in configuration"
    integrity = settings.security.integrity
    if integrity.enabled:
        modules.append(
            IntegrityMonitor(integrity, database.baseline("integrity"), policy(settings, integrity))
        )
    else:
        off["integrity"] = "disabled in configuration"
    exposure = settings.security.exposure
    if exposure.enabled:
        accepted = database.baseline("exposure", "accepted") or {}
        modules.append(
            ExposureAnalyzer(
                exposure, policy(settings, exposure), set(accepted.get("finding_ids", []))
            )
        )
    else:
        off["exposure"] = "disabled in configuration"
    ransomware = settings.security.ransomware
    if ransomware.enabled and ransomware.directories:
        modules.append(RansomwareMonitor(ransomware, policy(settings, ransomware)))
    else:
        off["ransomware"] = (
            "no directories configured (security.ransomware.directories)"
            if ransomware.enabled
            else "disabled in configuration"
        )
    return modules, off
